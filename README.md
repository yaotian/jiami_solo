# 文华 WT8 指标加密工具

Win10/Win11 x64 · 离线授权 · 单 exe 分发

## 架构

```
管理端 (WPF) → build_client.py → 客户端 Launcher.exe
  → 启动 WT8 → 注入 Hook DLL → 内存虚拟指标文件
```

## 环境要求

- Windows 10/11 x64
- Visual Studio Build Tools + Windows 10 SDK（编译客户端）
- Python 3 + `pip install cryptography`
- .NET Framework 4.8（管理端）

## 快速开始

### 1. Python 自检

```bash
python tools/wh_pack.py selftest
```

### 2. 命令行生成客户端（稳定基线 v5）

正式指标请使用文华设查看密码后的 `.XTRD`（见 [WT8 Spike](docs/WT8_SPIKE.md) 稳定基线 v5）：

```bash
python tools/build_client.py \
  --xtrd build/MYTEST.XTRD \
  --user "张三" \
  --contact "微信: xxx" \
  --indicator-version "1.0.0" \
  --expire 0 \
  -o dist/integration_client_v5.exe
```

调试可用 `--src build/test_indicator.myl`（明文 XTRD，无查看密码结构）。

### 多指标打包

多次传入 `--xtrd` 或 `--src` 即可生成内含多个指标的 exe，运行后在 WH8 中显示为 `TYPES\软件名称\*.XTRD`：

```bash
python tools/build_client.py \
  --xtrd build/MYTEST.XTRD \
  --xtrd build/WH8CRYPTO.XTRD \
  --software-name "WH8CryptoSuite" \
  --user "张三" --contact "微信: xxx" \
  --indicator-version "1.0.0" --expire 0 \
  -o dist/张三_多指标.exe
```

### 一机一码绑定

生成 exe 时填入客户机器码（26 位），客户端启动自动校验；也可留空由用户首次运行时手动输入注册码：

```bash
python tools/build_client.py \
  --xtrd build/MYTEST.XTRD \
  --machine-code "ROKZ3AIAJ6OY6QYNAA7UBKCCME" \
  --user "张三" --contact "微信: xxx" \
  --expire 0 \
  -o dist/张三_绑定版.exe
```

### 3. 管理端 GUI

打开管理端后：

- 左列（系统相关）：填写软件名称、软件版本、联系方式、主密钥、输出 exe 路径；
- 右列（客户相关）：填写用户名、授权天数、客户机器码、注册码；
- 点击「添加加密指标」按钮，选择已在 WH8 中设过查看密码的 `.XTRD` 文件，可一次选多个；
- 点击「生成客户端 exe」，默认生成到桌面，文件名包含软件名称、用户名和版本；
- 每次生成成功后，客户记录会自动保存到 `data/customers.json`，方便后续查询、续期或补发注册码。

> 建议先把指标在 WH8 里设密码保存为 `.XTRD`，再在管理端中添加并二次加密。

```bash
msbuild src/manager/WHCryptoManager.csproj /p:Configuration=Release
# 运行 src/manager/bin/Release/指标加密工具管理端.exe
```

## 升级 / 续期

1. 管理端修改源码或授权天数
2. 重新生成 exe
3. 客户替换旧 exe

## 文档

- [WHPKG 格式](docs/WHPKG.md)
- [WT8 Spike 实测](docs/WT8_SPIKE.md)
- [用户加白名单说明](docs/AV_WHITELIST.md)

## 注意

- **Hook 稳定基线：v5.0.17**（`dist/integration_client_v5*.exe`），详见 [WT8 Spike 稳定基线](docs/WT8_SPIKE.md#稳定基线-v50172026-06-20)
- 修改 Hook 时勿加回 `CloseHandle`/`WriteFile` 等已证实会导致 WH8 退出的 API
- 无代码签名，可能被杀软误报，见白名单说明
- 命令行/管理端生成后建议运行 `python tools/integration_test.py` 做集成自检
