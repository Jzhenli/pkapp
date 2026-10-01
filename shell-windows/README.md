# shell-windows — pkapp Windows C++ 壳 ★v8.2★

协议 A（v1.2）的 Windows 实现。壳 = **dumb loader**：只做"让一个可信的 Python 在正确的位置醒来"，不理解 app 语义。本目录是 M1 交付物，对应方案 v8 §5.5 四阶段路线中的 Windows 壳模板。

**事实源**（行为差异以文档为准）：

| 文档 | 地位 |
|---|---|
| `docs/SHELL_PROTOCOL.md`（v1.2） | 壳 ⇄ applocal 契约唯一事实源 |
| `docs/PACKAGER_SPEC.md`（v0.4） | spk 打包格式 |
| `docs/pkapp打包方案v8.md` §5.5 | 总体路线 |

> 本文 bat 示例统一用 `%REPO%` 指仓库根；复制前先 `set "REPO=<仓库根路径>"`。

## 目录结构

```
shell-windows/
├── build.bat              # 一键构建（需 cwd=shell-windows），产出 build\MyApp.exe + WebView2Loader.dll
├── src/
│   ├── shell.cpp          # 壳主体：九步引导（§3）+ ready 轮询/判死分档（§5）+ diag（§9）
│   │                      #   + stdio 重定向（§7）+ WebView2 窗口与握手码导航（§8）+ --selftest
│   ├── sha256.c/.h        # SHA-256（spk_hash 重算，PACKAGER_SPEC §6）
│   ├── ed25519.c/.h       # Ed25519 验签（TweetNaCl 子集，零依赖）
│   ├── spk.c/.h           # spk 读取：zip STORED 直读 + manifest 键解析 + spk_hash 同法重算
│   └── manifest.h/.c      # manifest 键提取（python_dll / entry 等，禁止壳内硬编码）
├── third_party/           # WebView2 SDK：WebView2.h + WebView2Loader(.dll/.lib)
├── tests/
│   └── test_shell_contract.py   # 15 例差分契约测试（§12.2①②③）
└── build/                 # 构建产物（MyApp.exe + WebView2Loader.dll）
```

## 构建

前置：**VS2022 BuildTools（含 C++ x64 工具集）+ Windows SDK + WebView2 SDK 头与 Loader**（已随仓附带在 `third_party/`）。

```bat
cd /d %REPO%\shell-windows
build.bat            :: 默认 MyApp；build.bat MyApp2 改产物名
build\MyApp.exe --selftest          :: 算法向量自检（SHA-256 / Ed25519 / spk_hash）
```

要点：纯 C17 + C++17、**/MT 静态 CRT**（避免 CRT 实例分裂导致 stdio 重定向静默失效）、GUI 子系统、仅依赖系统库 user32/gdi32/advapi32/bcrypt/ole32/shell32 + WebView2Loader.dll。

## 四阶段路线（本目录已全部走通）

```
① 真 PBS 快照   —— 使用 python-build-standalone 3.12.14 真运行时（非 mock DLL）
② 差分契约      —— tests/test_shell_contract.py：壳侧零依赖 C 实现与 pkapp.packager
                   （Python cryptography）对拍；正例验签链一致，负例（篡改/缺键/非
                   STORED/路径穿越/垃圾文件）必须拒绝
③ 九步引导      —— §3 全序：互斥→验签→指纹/解压→预清理→env→stdio→LoadLibraryEx
                   →记账→bootstrap→PyEval_SaveThread；8.5 ready 等待；9 心跳消费
④ e2e           —— 真 spk + 壳启动 → ready → 握手导航 → 健康页可见
```

## 线程模型四注记（协议 §11）

1. **V1 致命条款**：bootstrap 返回后立即 `PyEval_SaveThread()`，主线程此后**永不持有 GIL**（`PyRun_SimpleString` 要求持 GIL 且不自动释放——本机实证）。
2. **主线程 WM_TIMER 轮询**（500ms 节拍），协议**禁止独立轮询线程**——独立线程会把大依赖慢启动 import 误杀在 30s 判死窗口内；冷启动超时独立档（默认 120s）。
3. **心跳在 applocal 后台线程**：只有 uvicorn 所在进程能真实探测 uvicorn；壳只消费 ready（seq 判活主判据，30s 无增长 / ready 消失 / ready{false} → 判死 → diag 错误页）。
4. **退出一律 `ExitProcess`，不做 `Py_Finalize`**（uvicorn 后台线程下 Finalize 是经典死锁源）。

## e2e 手工复现

```bat
:: 1) 重建真 spk（cwd 必须在 %REPO%\pkapp，避免被仓库根的 pkapp 命名空间目录 shadow）
cd /d %REPO%\pkapp
%REPO%\.venv\Scripts\python.exe -m pkapp.tools.make_runtime_proto ^
    %REPO%\runtimes\python --outdir %REPO%\out\e2e ^
    --key %REPO%\.pkapp\sign.key

:: 2) 组装安装目录三件套
mkdir %REPO%\out\e2e\MyApp
copy %REPO%\shell-windows\build\MyApp.exe        %REPO%\out\e2e\MyApp\
copy %REPO%\shell-windows\build\WebView2Loader.dll %REPO%\out\e2e\MyApp\
copy %REPO%\out\e2e\MyApp.spk                    %REPO%\out\e2e\MyApp\
:: _runtime 展开区由壳首启自动解压（staging → 原子 rename）

:: 3) 运行并观察
%REPO%\out\e2e\MyApp\MyApp.exe
:: 日志：%LOCALAPPDATA%\MyApp\cache\log\MyApp-YYYYMMDD.log（含 CI 锚点 PRE-INIT-PROBE）
:: ready：%LOCALAPPDATA%\MyApp\cache\ready；诊断：%LOCALAPPDATA%\MyApp\cache\diag.json
```

## 实测注记（e2e 踩坑沉淀）

- **Defender 瞬时握柄**：新解压文件可能被 Defender 扫描短暂占用 → `promote_staging` 已带重试（错误码 5/32/33 × 10 次 × 500ms）。
- **GUI 子系统 stdio**：printf 走 FILE* 层会静默丢失（fd 层 `_write` 正常）→ 已改 `_wfreopen` 双保险，FILE* 与 fd 1/2 一并重绑（协议 §7）。
- **安装目录三件套**：`MyApp.exe` + `WebView2Loader.dll` + `MyApp.spk`。**严禁**在安装目录放任何 `*.py` / 包目录 / `DLLs` 目录 / `<EXE-stem>._pth`（协议 §2.1 V15：executable_dir 会进 `sys.path`）。

## 契约测试运行

```bat
:: 前置：build.bat 已产出 build\MyApp.exe
cd /d %REPO%\pkapp
%REPO%\.venv\Scripts\python.exe -m pytest ../shell-windows/tests/test_shell_contract.py -q
```

## 文档映射

| 源码 | 协议章节 |
|---|---|
| `shell.cpp` 单实例互斥 | §3 步骤 0（v8.0 R21） |
| `shell.cpp` 验签链（format_version→Ed25519→版本单调→spk_hash） | §3 步骤 1、§12.2 |
| `spk.c` spk_hash 同法重算 | PACKAGER_SPEC §6 |
| `shell.cpp` 指纹三规则 / promote_staging | §3 步骤 2、§4 四铁律 |
| `shell.cpp` stdio 重定向 + PRE-INIT-PROBE | §7（v8.1 V8 双保险） |
| `shell.cpp` ready 状态机（PH_COLD/PH_RUNTIME/PH_DEAD） | §5（v8.1 V6/V7） |
| `shell.cpp` diag_write/diag_read_summary | §9 |
| `shell.cpp` 握手码导航（每次导航重写） | §8 |
| `--selftest` / `--selftest-spk` | §12 测试形态 |
