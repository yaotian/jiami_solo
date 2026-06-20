# WHPKG v2 二进制格式

Magic: `WHPKG\0\1\0` (8 bytes)

| 字段 | 类型 | 说明 |
|------|------|------|
| version | uint32 LE | 当前 = 2 |
| header_len | uint32 LE | header 区长度 |
| product_id | uint32 LE | 1=T8/WH8 |
| expire_unix | int64 LE | UTC 到期秒，0=永久 |
| user_len + user | uint16 + UTF-8 | 用户名 |
| contact_len + contact | uint16 + UTF-8 | 过期联系方式 |
| indicator_version_len + ver | uint16 + UTF-8 | 指标版本 |
| software_name_len + name | uint16 + UTF-8 | 客户端软件名称，作为 `TYPES\软件名称\` 目录 |
| nonce_len | uint8 | 固定 12 |
| nonce | 12 bytes | GCM nonce |
| tag | 16 bytes | GCM tag |
| ct_len + ciphertext | uint32 + bytes | 加密 payload |

Payload 明文: `[src_len:4][src][note_len:2][note]`

密钥: `HKDF-SHA256(master_key, salt="WH-PAYLOAD", info=user)`

---

# WHBUNDLE v1 二进制格式（多指标 exe 内嵌包）

一个 exe 客户端资源中内嵌多个 WHPKG 时使用。Launcher 解析后按 `software_name` 创建 `Formula\TYPES\软件名称\` 目录，并写入多个指标占位文件；Hook 按文件名路由到对应 WHPKG。

Magic: `WHBUNDLE\0\1\0` (11 bytes)

| 字段 | 类型 | 说明 |
|------|------|------|
| version | uint32 LE | 当前 = 1 |
| software_name_len + name | uint16 + UTF-8 | 客户端软件名称，作为 `TYPES\软件名称\` 目录 |
| count | uint32 LE | 指标数量 |
| name_len + filename | uint16 + UTF-8 | 指标文件名（如 `WH8CRYPTO.XTRD`） |
| pkg_len + whpkg | uint32 + bytes | 单个 WHPKG v2 包 |
| ... | 重复 count 次 | |

Hook 与 Launcher 通过共享内存 `WHSM\0` v3 传递：master_key(32) + virtual_dir + bundle 全长。

---

# 一机一码离线注册码 v1

把客户端绑定到单一机器，全程无需联网。注册码由管理端用主密钥生成，可嵌入 exe，也可让客户首次运行时手动输入。

## 机器码

- 采集项：CPU 信息 + 系统盘卷序列号；若 WMI 能读到主板序列号，也混入输入。
- 对输入做 SHA256，取前 **16 字节**。
- 16 字节经 Base32（大写、无填充）编码，得到 **26 位字符串**。
- 示例：`ROKZ3AIAJ6OY6QYNAA7UBKCCME`

C++ 客户端运行时会重新计算本机机器码，并与注册码中的 `machine_hash` 比对。

## 注册码格式

原始二进制 38 字节，最后经 URL-safe Base64（无填充）输出为字符串。

| 字段 | 偏移 | 长度 | 说明 |
|------|------|------|------|
| magic | 0 | 4 | `WHLC` |
| version | 4 | 1 | `1` |
| machine_hash | 5 | 8 | 机器码 SHA256 前 8 字节 |
| expire_unix | 13 | 8 | UTC 到期秒，`0` = 永久 |
| flags | 21 | 1 | 预留，默认 `0` |
| signature | 22 | 16 | HMAC-SHA256(master_key, 前 22 字节) 前 16 字节 |

签名仅用于防篡改，不暴露主密钥本身。

## 使用方式

1. 客户首次运行未绑定的客户端，会弹出「本机机器码」；复制给开发者。
2. 开发者在管理端填入机器码并生成注册码（或直接用 `tools/wh_license.py`）。
3. 交付方式二选一：
   - **预嵌入**：生成 exe 时提供 `--machine-code`，客户端自动完成校验。
   - **手动输入**：不嵌入注册码，客户端弹出输入框；验证通过后写入注册表 `HKCU\Software\WH8Crypto\LicenseKey`，后续自动读取。
4. 到期日、机器码任一不匹配，客户端拒绝运行并提示联系方式。

## 实现文件

| 端 | 路径 |
|----|------|
| C++ 机器码 | `src/cpp/launcher/wh_hwid.h` / `wh_hwid.cpp` |
| C++ 注册码 | `src/cpp/launcher/wh_license.h` / `wh_license.cpp` |
| Python 参考/脚本 | `tools/wh_license.py` |
| C# 管理端 | `src/manager/Crypto/WhLicense.cs` |
| 集成测试 | `tools/integration_test.py` |

## CLI 示例

```bash
python tools/build_client.py \
  --xtrd build/MYTEST.XTRD \
  --machine-code "ROKZ3AIAJ6OY6QYNAA7UBKCCME" \
  --user "张三" --contact "微信: xxx" \
  --expire 0 \
  -o dist/张三_绑定版.exe
```

若同时提供 `--license-key`，则直接嵌入该注册码而不再自动按机器码生成。
