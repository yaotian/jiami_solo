# WT8 Spike 实测记录

## 稳定基线 v5.0.17（2026-06-20）

**测试结论：MYTEST 与 WH8CRYPTO 在挂 K 线并切换 15+ 标的后均稳定，WH8 不退出。**

**测试流程：**

1. 完全退出 wh8（任务管理器确认无 `wh8.exe`）
2. 重新打开 wh8
3. 运行客户端 `integration_client_v5*.exe`（Hook 版本 5.0.17）
4. 先加载 MYTEST，挂 K 线后切换 15+ 个标的 → 稳定
5. 再加载 WH8CRYPTO → 稳定

**意义：** 证明当前全局 kernel32/kernelbase MinHook 方案在 v5.0.17 策略下与 wh8 切换场景兼容，暂不需要切换到 `whcall.dll` 目录部署或按需注入方案。

## 稳定基线 v5.0.6（2026-06-20）

**v5.0.5 问题：** 日志 `CreateFileA tracked WH8CRYPTO` ×4 后 wh8 无日志退出。疑因全局 `CloseHandle` Hook 在句柄关闭后仍被 ReadFile，或 `DuplicateHandle` 产生未跟踪句柄读到 WHPKG。

**v5.0.6 修复：** 移除 `CloseHandle` Hook；新增 `DuplicateHandle` Hook；ReadFile/CreateFileMapping 对未跟踪句柄按路径补跟踪；打开非 WH8CRYPTO 文件时 untrack 防句柄复用污染。

## 稳定基线 v5.0.5（MFC 可加载，但加载后仍可能退出）

**v5.0.4 问题：** 「加载 >>」报 MFC `filecore.cpp:137` 析构异常。日志为 `CreateFileA virtual WH8CRYPTO`——虚拟句柄与 MFC `CFile` 不兼容。

**v5.0.5 修复：** 改回**真实磁盘句柄** + `ReadFile` 等拦截；新增 `GetFileInformationByHandle(Ex)` / `FlushFileBuffers` 统一返回明文 XTRD 大小；保留 `CloseHandle` 句柄清理与 refresh 不清表。

## 稳定基线 v5.0.4（已废弃 — MFC 加载失败）

**v5.0.3 问题：** 日志仅 `hook_install ok`，指标已上 K 线仍退出。根因是 `CreateFile` 打开磁盘 WHPKG 真句柄 + `hook_refresh_payload` 清空句柄表，WH8 后台重读时落到磁盘乱码。

**v5.0.4 修复：** `CreateFileW/A` 对 WH8CRYPTO **直接返回虚拟句柄**（不读磁盘 WHPKG）；虚拟句柄 `CloseHandle` 不调系统 API；刷新 payload 不再清空句柄表。

## 稳定基线 v5（2026-06-20，务必保留）

**结论：注入 Hook 后连续点击多个自编指标（含 MYTEST），WH8 不再自动退出。**

| 项目 | 值 |
|------|-----|
| 客户端产物 | `dist/integration_client_v5.exe` |
| Hook DLL 部署 | `{WH8安装目录}\wh8crypto_v5.dll` |
| 打包输入 | `--xtrd` 文华设查看密码后的 XTRD（如 `MYTEST.XTRD`） |
| 磁盘占位 | `自编\WH8CRYPTO.XTRD` = **WHPKG 二次加密乱码**（非明文 XTRD） |

### v5 Hook 策略（勿随意加回已删 API）

**已 Hook（仅 WH8CRYPTO 句柄生效，其它指标走原函数）：**

- `CreateFileW/A`（跟踪句柄 + `CREATE_ALWAYS`→`OPEN_EXISTING` 防清空 WHPKG）
- `ReadFile` / `GetFileSize` / `GetFileSizeEx`
- `SetFilePointer` / `SetFilePointerEx`
- `CreateFileMappingW/A`
- `CloseHandle` — **仅**从句柄跟踪表移除 WH8CRYPTO 相关项（v5.0.3 修复加载后延迟退出）

**刻意不 Hook（会导致 WH8 退出或不稳定）：**

- `CloseHandle` 内不得做除 untrack 以外的逻辑
- `WriteFile` / `SetEndOfFile` — 更新主图保存路径曾触发崩溃
- `DeleteFileW`

**运行时规则：**

- MinHook **只安装一次**；重复运行客户端仅 `hook_refresh_payload`，**禁止**在 WH8 运行中 `MH_Uninitialize`
- 句柄表 + 打开 WH8CRYPTO 时才校验路径，避免误伤 MYTEST 等其它指标

### 推荐测试 / 使用流程

1. **完全退出 wh8**（任务管理器确认无 `wh8.exe`）
2. 重新打开 wh8
3. 运行 `integration_client_v5.exe`

**重要：** 若 wh8 进程中已有 `wh8crypto*.dll`（例如测过 v5.1 未重启 wh8），客户端会拒绝注入并提示重启；否则内存里仍是旧 Hook，会误报「v5 也会退出」。

4. 先点多几个普通指标确认稳定，再试 WH8CRYPTO（K 线加载，勿用更新主图）

### 编译命令（稳定配置）

```bash
python tools/build_client.py \
  --xtrd build/MYTEST.XTRD \
  --user "测试" --contact "微信:xxx" \
  --indicator-version "1.0.0" --expire 0 \
  -o dist/integration_client_v5.exe
```

### v5.1（已废弃 — 会导致 wh8 退出）

曾增加 `WriteFile`/`SetEndOfFile` 快速路径 Hook 以支持「更新主图」保存，实测：**点多几个指标后 wh8 仍会退出**。  
结论：**不得 Hook WriteFile/SetEndOfFile**，稳定基线仍为 **v5**。

「更新主图」后续方向：K 线加载指标（不经过公式保存），或改为原版 whcall.dll 式部署（非全局 kernel32 Hook）。

### v5 尚未验收

- [ ] WH8CRYPTO 公式编辑 → 更新主图
- [ ] 记事本打开 WH8CRYPTO.XTRD 为 WHPKG 乱码
- [ ] 过期弹窗

---

## 测试环境（已确认）

| 项目 | 值 |
|------|-----|
| 安装路径 | `D:\WT8模拟版\` |
| 主进程 | **`wh8.exe`** |
| 指标目录 | `D:\WT8模拟版\Formula\TYPES\` |
| 自编列表 | `D:\WT8模拟版\Formula\TYPES\自编\*.XTRD` |
| 列表索引 | `D:\WT8模拟版\Formula\TYPES\自编\Order.ini` |
| 文件后缀 | `.XTRD` / `.xtrd` |
| 操作系统 | Windows 10/11 x64 |

## 指标部署路径

| 项目 | 值 |
|------|-----|
| 自编目录 | `Formula\TYPES\自编\` |
| 指标文件 | **`WH8Crypto.XTRD`**（磁盘为加密 WHPKG 占位） |
| 列表注册 | 向 `自编\Order.ini` 追加 `ITEMxxxx=WH8Crypto.XTRD` |
| 运行时解密 | Hook 拦截 WH8CRYPTO 的 `ReadFile` 等，内存返回带查看密码的 XTRD |

WT8 左侧「自编」= `自编` 文件夹内 **扁平 XTRD 列表**（由 `Order.ini` 排序），不是 TYPES 根下的子文件夹树。

## 待实测

- [x] 运行客户端后 `自编\WH8CRYPTO.XTRD` 是否出现
- [x] `Order.ini` 是否增加 WH8CRYPTO 条目（自动去重）
- [x] 自编列表是否显示 WH8CRYPTO（无需手动点「更新」）
- [x] 双击 WH8CRYPTO 能否加载到图表
- [ ] 记事本打开磁盘文件是否为乱码（加密占位）
- [ ] 过期弹窗（将系统时间调到到期日后运行客户端）

## 实测结论

- **稳定 Hook 基线见上文「稳定基线 v5」**；v3/v4 会导致 WH8 自动退出，勿回退
- XTRD 须含 `<HEAD>`+密文 `<CODE>`（文华查看密码）；打包用 `--xtrd`，磁盘仍为 WHPKG
- Order.ini 与 WT8「更新」扫描可能重复登记，已统一为 `WH8CRYPTO.XTRD` 并去重
