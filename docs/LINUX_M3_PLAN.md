# Linux 平台（M3）设计与实现计划——评审稿

状态：评审稿 v4（2026-10-18；十二项决策点待拍板，见 §7；拍板后可开工）
日期：2026-10-14（v2 修订 2026-10-17；v3 修订 2026-10-18：armv7 板子线；v4 修订 2026-10-18：armv7 构建口径与 D-12 改判）
关联文档：pkapp打包方案v8（§5.7 无壳路线作废说明）、BOOTSTRAP_INTEGRITY_PLAN §6/Q6/Q7/Q8、SHELL_PROTOCOL（协议 A）、PACKAGER_SPEC、ANDROID_7x24_WATCHDOG_PLAN（L2 进程外前车）
真实部署目标：x86_64 服务器 + **glibc 2.31 的 armv7 开发板**（见 D-8 / D-12）

---

## 0. 一句话

Linux 以 **launcher ELF**（headless 壳，与 Windows 壳同源 C）为 native 信任根：验签 → 解包 → 清单校验 → dlopen libpython → keylib 解密引导 → in-process 运行 Python + 心跳监督，死亡/死锁交 systemd 重启；产物 = tar.gz 部署目录（launcher + spk + 完整性侧车 + systemd 模板）。

```
launcher ELF（native 信任根，进程常驻）
  → spk 验签（Ed25519，ed25519.c/spk.c 直接复用）
  → 指纹比对 / 全量解包（staging → 原子 rename）
  → 清单侧车验签 + 递归对称差 + 定向 purge（P0 契约，integrity.c 复用）
  → dlopen(libpython3.12.so.1.0, RTLD_NOW|RTLD_GLOBAL) + dlopen(pkapp_key.so)
  → 铺 MYAPP_* env 契约（目录决策权在壳）
  → PyRun 引导（keylib 解 _codekey → import applocal; bootstrap）
  → 心跳消费（ready seq 主判据）→ 判死 → diag + exit(非0) → systemd Restart
UI = 用户浏览器（server/headless 无窗口；首启 URL + 握手码输出——去向见 D-10）
监督边界：覆盖 Python 层死锁/挂起；不覆盖进程级 freeze（除非采纳 D-6）
```

---

## 1. 背景：为什么"无壳"作废

- 方案 v8 §5.7 原定 Linux = 无壳（启动脚本 `exec -a` + systemd 模板，~25 行 bash）；
- BOOTSTRAP_INTEGRITY_PLAN §6（2026-10-07 评审定稿）推翻该假设：P0 完整性体系要求**每个平台都有 native 信任根**——无壳则 Linux 是唯一既没有 spk 验签执行者、也没有清单校验执行者的平台；
- 结论：**launcher ELF 从可选变必选**，"启动脚本铺 env"路线一并作废（§4.1 有替代设计）；
- 工作量影响：较"纯脚本"方案增加约 3–5 人日（launcher 本体），但换来与 Windows/Android 对齐的信任根与心跳监督语义。P0 已消险：五个 C 模块实际均按可移植写法落地（★措辞校正★：Q6 原文只给"验哈希"单模块立了可移植性先例，五模块全量可移植是代码事实而非 Q6 拍板结论）。

---

## 2. 现状盘点

### 2.1 已就位（零成本或近零成本复用）

| 件 | 位置 | 说明 |
|---|---|---|
| 五个可移植 C 模块 | `shell-windows/src/{sha256,ed25519,spk,manifest,integrity}.c` | ★已核实★仅 `spk.c` L11-13 一处 `#ifdef _WIN32`（`<windows.h>` + `_wfopen`），且 L36-38 已有 POSIX `#else`，其余纯标准 C；launcher 直接编译。建议抽到共享 `native/` 目录，避免 shell-linux 反向依赖 shell-windows |
| P0 完整性落地先例 | `shell.cpp`（dont_write_bytecode / 侧车 / purge；完整性门在 **步骤 2.5**，L2351-2353） | 语义照搬，POSIX 化实现 |
| 公钥锚点补丁 | `package.py` `_patch_shell_pubkey`（L190，调用点 L310） | 纯字节等长原位改写（64-hex 常量段），对 ELF 同样适用；★前提★该段在编译后 ELF 内唯一且连续可定位，需补断言测试（见 §8 R-L9） |
| keylib linux 编译路径 | `keybuild.py` `_compile_linux` | cc/gcc，POSIX 构建机可用 |
| AppSpec linux 字段 | `appspec.py`（`[platforms.linux]`、`linux_setproctitle` 默认 True，L89） | 已存在；★但 `setproctitle` 无消费代码（不追加依赖、不进 manifest），见 §4.5 |
| CLI 选项 | `cli.py`（build/package 已含 linux 位置参数） | 只差实现；`fetch` choices 仍缺 linux（L68） |
| applocal POSIX 基础 | `_core._bind_socket` SO_REUSEADDR（POSIX 分支已做，L141/L152）；`set_process_title()` 已有 Linux 分支（`_core.py` L476-483，调用点 L541-545） | 纯 Python 包基本平台无关；★目录决策权不在 applocal★——`_env.py` L183-193 只做必填 env 读取（无 XDG / 无 expanduser），XDG 归 launcher（见 §3.1 步 4） |
| 心跳协议 | SHELL_PROTOCOL §5/§6（ready JSON、seq 主判据、30s 判死） | 平台无关文件协议，launcher 只消费 |

### 2.2 缺口（全部待实现）

- `assemble.py`：linux 分支直接 raise（L926）；
- `toolchain.py`：fetch 无 linux 选项、PBS linux 无 PINS；
- `package.py`：linux → tar.gz 打桩未实现（L253）；
- launcher ELF 本体 + `shell-linux` 构建工程；
- **linux 架构维度**：现只有 android 有 `abis`（`Pin.platform` 注释写死 `windows | android`，`_wheels_cache("linux")` 无 arch 子层）——加 aarch64/armv7 前须先定模型（R-L17）；
- launcher：`MYAPP_*` env 契约铺设（目录决策权在壳，applocal 只做必填校验，见 §3.1 步 4 表）；
- applocal：`set_process_title` 标题改为取应用名（现硬编码 `myapp`，`_core.py` L543）；
- 公钥锚点补丁对 ELF 的断言用例（`-fPIC` / `-O2` / strip 后常量段仍唯一可定位）；
- CI：`release.yml` 与 **`ci.yml`** 均仅 windows-latest（`ci.yml` L14 matrix 注释"后续可加 ubuntu"），缺 ubuntu job → 三平台契约测试无 CI 承载。

---

## 3. 总体形态：launcher ELF = headless 壳

### 3.1 与 Windows 壳九步职责对账

| 步 | Windows 壳（shell.cpp） | Linux launcher |
|---|---|---|
| 0 单实例互斥 | 命名互斥量 | `flock(<data_dir>/lock)`；失败直接退出（无窗口可激活） |
| 1 验签 | format_version → Ed25519 → 单调性 → spk_hash | 同（五模块复用，零改动） |
| 2 指纹/解压 | staging → 原子 rename | 同（POSIX rename 原子性更强；staging 须与 `_runtime/` 同目录同文件系统，否则 rename 退化为拷贝） |
| 2.5 引导面完整性门 | 侧车验签 → 递归对称差 → 定向 purge（`shell.cpp` L2351-2353） | 同（★原表漏列此步，launcher 实现易漏★） |
| 3 预清理 | 旧 ready / 旧握手码 | 同 |
| 4 环境变量 | `SetEnvironmentVariableW`（L2384-2389） | `setenv` 铺**全套 `MYAPP_*` 契约**（下表）；缺任一必填项 applocal 即 `ContractError` |
| 5 stdio 重定向 | `_wfreopen` | `dup2` → `<cache>/log/<app>-*.log`；★与 journald 冲突★：dup2 后 stdout 不再进 journald，握手 URL / diag 的去向须定（见 D-10） |
| 6 加载解释器 | `LoadLibraryExW(python312.dll)` | `dlopen("libpython3.12.so.1.0", RTLD_NOW \| RTLD_GLOBAL)`（★GLOBAL 必需★：否则后续 dlopen 的 C 扩展解析不到 `Py*` 符号） |
| 7 记账 | runtime.version（指纹规则③′） | 同 |
| 8 PyRun 引导 | keylib.dll 解 `_codekey` → PyRun | 同（`dlsym` 取 `Py_*` 符号；keylib 用 `dlopen`） |
| 8.5 等待 ready | seq 主判据 + 冷启 120s 档 | 同 |
| 9 心跳消费 | 泵内计时判死 → 错误页 | watchdog 线程判死 → diag + `exit(非0)` → systemd `Restart=on-failure` |

**步骤 4 `MYAPP_*` env 契约（launcher → applocal，逐一核对 `_env.py` L170-203）**

| env | 必填 | launcher 取值 |
|---|---|---|
| `MYAPP_PLATFORM` | ✅ 必填 | 常量 `linux`（`_PLATFORMS` 已含） |
| `MYAPP_DATA_DIR` | ✅ | `<data>`（XDG 或 StateDirectory，见 D-9） |
| `MYAPP_CACHE_DIR` | ✅ | `<cache>` |
| `MYAPP_LOG_DIR` | 可选 | 缺省 `<cache>/log` |
| `MYAPP_READY_FILE` / `MYAPP_DIAG_FILE` | ✅ | `<cache>/ready` / `<cache>/diag.json` |
| `MYAPP_HANDSHAKE_FILE` | 可选 | `<cache>/handshake` |
| `MYAPP_STATIC_DIR` / `MYAPP_MANIFEST_PATH` | ✅ | 解包区内 `dist/` 与 `manifest`；★`app_dir` 由 `_env.py` L192 推导 = `dirname(MANIFEST_PATH)/app`★，§4.4 布局须满足 |
| `MYAPP_VERSION` | ✅ | spk manifest 版本 |
| `MYAPP_PORT` / `MYAPP_BIND` / `MYAPP_LAN` / `MYAPP_AUTH` … | 可选 | 取 manifest 或运维 env（env 优先） |
| `MYAPP_NATIVE_LIB_DIR` | 可选 | 解包区内 native 目录 |
| `MYAPP_INTEGRITY_PURGE` | 条件 | ★口径待确认★：Windows 侧实为 **环境变量**（`shell.cpp` L2399-2406），本文档 §4.3 原写"经启动参数"——in-process 嵌入无子进程 argv，Linux 应同法 `setenv` |

### 3.2 与 Windows 壳的职责差（不做 / 改做）

| Windows 壳职责 | Linux launcher 处理 |
|---|---|
| WebView2 窗口 / 错误页 UI / 启动加载层 / 导航 | **无**。UI = 用户浏览器；校验失败 fail-closed = 写 diag + exit 非零（journal 可查），无错误页 |
| 握手码自动导航 | **改打印**：ready 后向 stdout/journal 输出 `http://127.0.0.1:<port>/?handshake=<code>`（首启登录入口；一次性语义不变） |
| 单实例激活首实例窗口 | **改为纯互斥**：flock 失败即退出（headless 无窗口可前置）；★注意★退出非零会被 systemd 判为失败再重启，重启窗口内易形成抖动——建议 flock 失败后短重试（≤ `RestartSec`）或按 D-11 口径区分退出码 |
| WebView2 环境/版本探测 | 无 |

### 3.3 运行模型：in-process，无 fork

与 Windows 同构：launcher **dlopen libpython 后在本进程内**初始化并运行 Python（非 fork/exec 子进程）。监督 = 进程内 watchdog 线程轮询 ready 文件（SHELL_PROTOCOL §5：seq 主判据、30s 无增长 / ready 消失 / ready{false} 判死），判死后写 diag、退出非零，由 systemd 接管重启。**不做 L0/L1/L2 分档**（见 §7 D-1）。

> ★in-process 监督的能力边界（评审补充，见 §8 R-L12）★
> - 能覆盖：Python 层死锁 / 死循环 / 健康探针失败（watchdog 是 native pthread，不受 GIL 与 Python 死锁影响）；
> - **不能覆盖**：进程级冻结（`SIGSTOP`、cgroup freezer、整机 hang）——watchdog 线程随进程一并冻结，无人计时退出。Android 侧 L2 之所以做成进程外（`shell-android/.../Watchdog.kt` 注释"L2 进程外兜底"）正是此因。
> - 结论：验收项不得用 `SIGSTOP`（原 §9.3 已修正）；若要覆盖冻结，走 systemd 原生硬件看门狗（D-6）。

---

## 4. 关键设计

### 4.1 解释器嵌入与 POSIX `._pth`（★建议新增决策 D-5★）

- v8 原定"启动脚本铺 PYTHONHOME/PYTHONPATH"，随无壳方案作废。launcher 化后若仅靠 env 铺路径，**P0 R1-9 的环境变量注入面（PYTHONPATH/PYTHONHOME/PYTHONSTARTUP）在 Linux 复活**——与 Windows 的隔离模式不对齐；
- 方案：产 **POSIX 形态 `._pth`** = `libpython3.12.so.1.0._pth`（3.11+ getpath 的 `._pth` 检测实为跨平台，POSIX 命名为"完整库文件名 + ._pth"，v8 §5.5 V3④ 已注记并预留"未来统一再评估"——即现在）；
- 收益：`._pth` 存在即隔离模式，env 注入面在 Linux 与 Windows 同步封死（★引用校正★：D5 定义在 BOOTSTRAP_INTEGRITY_PLAN **§5 L160**，§4.6 仅为其攻击面矩阵行）；路径钉死载体三端统一为 `_pth` 家族；
- 内容与 Windows 同构：`libpython3.12.so.1.0` 同目录 + stdlib zip + `site-packages/deps.zip`（或散件目录）条目，`site-packages/` 本身不上 sys.path；
- ★阶段 0 硬闸验证项★（评审细化，原表述只写了"解析基准"，未给可执行的枚举与判据）：
  1. **命中基准三选一实测**：① launcher 自身路径（`/proc/self/exe`）；② `libpython3.12.so.1.0` 所在目录；③ 显式设置 `PyConfig.program_name` 后的路径。嵌入场景 `program_name` 由 launcher 决定，很可能**不是**库文件名；
  2. **首选落地手段**：显式 `PyConfig.program_name` + 与之配套的 `._pth` 命名，把命中变成确定性行为，而非依赖 getpath 的默认探测；
  3. **隔离生效的可断言判据**（不接受"看着对"）：`sys.flags.isolated == 1`、`PYTHONPATH` 未出现在 `sys.path`、`sys.path` 精确等于 `._pth` 声明列表 + 必带项；
  4. **影响面**：若实测基准是 launcher 路径，D-5 与本节、`§5 assemble` 差异点中的 `._pth` 全名须同步改为 `<launcher 名>._pth`。

### 4.2 keylib 与加密链路

- 链路与 Windows 同构：launcher `dlopen(pkapp_key.so)` → 解 `_codekey` blob → PyRun 注入；`compile_keylib("linux")` 已有（`_compile_linux`，`keybuild.py` L137-142）；★命名★android 侧为 `lib_pkapp_key.so`，linux 侧文件名需与 `_find_keylib` 回退口径对齐；
- **约束**：keylib 每项目现场编译（K_app 烧入），不可 vendor 预编译 ⇒ 其 glibc 要求跟随构建机。文档写明：**部署目标 glibc ≤ 构建机 glibc**；
- ★glibc 一致性（评审补充）★：D-2 让 launcher 锁 2.17，D-3 却让 keylib 在 WSL2/CI 任意发行版上编译 → 实际底线被 keylib 抬高，R-L3 只靠文档约束并未真闭合。建议官方路径下 **keylib 与 launcher 在同一 manylinux2014 容器编译**；
- Windows host 构建 linux 目标 + `code_encryption=true` → **fail-fast**（★现状：尚未实现★——`assemble.py` L1112-1115 按构建机平台选 host，Windows 下恒走 `_compile_windows`；`produce_keylib` L185-198 编译失败还会退化为锚点补丁而非 fail-fast），报错文案指向 WSL2/CI（见 §7 D-3）；不加密封装时 Windows host 全功能可用（清单校验归 launcher，与加密无关）。

### 4.3 心跳监督与 systemd

- 判死语义与 Windows/Android 逐条一致（seq 30s / ready 消失 / ready{false}）；冷启动 120s 档同；
- 判死后：diag（写 `<cache>/diag.json` + boot-timing 通道）→ exit 非 0；
- `.service` 模板（package 期生成）：`Restart=on-failure`、`RestartSec=3`、`ExecStart=<部署目录>/myapp`、`User=`/`WorkingDirectory=` 占位、`KillSignal=SIGTERM`；`Type=simple`；
- ★可选增强（D-6）★：加 `WatchdogSec=<N>`，由 watchdog 线程周期性 `sd_notify("WATCHDOG=1")`（NOTIFY_SOCKET 协议，手写 ~30 行，无需链 libsystemd）→ **唯一能覆盖进程级冻结**的途径，零额外进程；不采纳则须在文档中明示"冻结不在监督范围"；
- 审计时序沿用 Q8（★口径修正★：Windows 侧实为环境变量 `MYAPP_INTEGRITY_PURGE`，`shell.cpp` L2399-2406；in-process 嵌入无子进程 argv，Linux 应同法 `setenv`），bootstrap 后由 Python 侧补审计（`_core.py` L541 `report_integrity_purge()`）。

### 4.4 部署布局与升级

```
/opt/myapp/
  └─ myapp-<ver>/                ← 版本化目录（tar.gz 解开的即此目录）
       ├─ myapp                  ← launcher ELF（公钥已补丁；文件名 = 进程标识）
       ├─ runtime.spk
       ├─ integrity.manifest(.sig)   ← 侧车，与 launcher 同级（Q7 合同）
       ├─ _runtime/              ← 首启解包展开区（指纹记账）
       │    ├─ manifest          ← MYAPP_MANIFEST_PATH（app_dir = _runtime/app，★原图漏★）
       │    ├─ app/ + site-packages/   └─ dist/  ← MYAPP_STATIC_DIR
       └─ myapp.service          ← systemd 模板
/usr/local/bin/myapp → /opt/myapp/myapp-<ver>/myapp   ← 符号链接，升级秒切（ln -sfn）
数据区 ~/.local/share/MyApp/  缓存区 ~/.cache/MyApp/（log/、ready、diag）
```

- ★符号链接与路径解析（评审补充，见 §8 R-L10）★：`/usr/local/bin/myapp` 是软链，`argv[0]` 与真实路径不一致；spk / 侧车 / 解包区一律以 **`realpath("/proc/self/exe")`** 为基准解析（Q7"与 ELF 同级"指真实文件所在目录），验收须含"经软链启动"用例；
- ★解包区可写性 × 部署权限分离（见 D-7 / R-L11）★：BOOTSTRAP_INTEGRITY_PLAN §9 要求"部署目录 owner 非应用运行账号"，但首启解包要写 `/opt/myapp/myapp-<ver>/_runtime/`。三选项见 D-7；
- ★D-7 选项③（迁 StateDirectory）核对结论★：`_runtime` 与 spk 同目录**不是契约，只是 Windows 壳的硬编码拼接**（`shell.cpp` L319 `g_runtime = join_path(g_install, "_runtime")`；staging 同目录 L487）。指纹记账 `runtime.version`（L1482）、`manifest`（L2202/L2395）、`python_dll`（L1466）、受保护树根（L2123）全在 `_runtime` 内自洽 → **解开成本低**；但受保护树随之迁入运行账号可写区（R-L18），需与 D-9 合并权衡；
- 升级 = 新版本目录解包到旁 → `ln -sfn` 切链 → `systemctl daemon-reload`（unit 随版本变化时）→ `systemctl restart myapp`；data/cache 按版本无关目录天然保留；
- 回滚与旧版本目录保留/清理策略：v1 不自动清理，写进部署文档；
- 安装不造 install 脚本（v1）：`.service` 内含注释行写明两步手工命令，复杂安装器列为后续项。

### 4.5 进程标识（v8 §5.8 契约；★该节正文为空，实质内容在 v8 L87 / L390★）

- `ps/top`：launcher 文件名即 `myapp`；Python 侧 `setproctitle` 把完整标题钉为 `myapp`；
- `systemctl`：`myapp.service`；三处显示一致；
- ★现状校正★：`linux_setproctitle` 虽默认 `True`（`appspec.py` L89），但**无任何消费代码**（不追加依赖、不入 manifest）；applocal 侧是无条件 `set_process_title("myapp")`（`_core.py` L543）——标题**硬编码**，非 `myapp` 应用下"三处一致"不成立。实现项：① 按 `linux_setproctitle` 决定是否装入 `setproctitle`；② 标题取自应用名而非常量。

---

## 5. 工具链改动面（文件级）

| 模块 | 改动 |
|---|---|
| `toolchain.py` | PBS linux pin（x86_64 预期 `cpython-3.12.14+20260929-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz`，文件名/sha256 以实际 release 清单实测回填）；fetch choices + snapshot 加 linux。**D-8 拍板后按架构各加一条 pin**：`aarch64-unknown-linux-gnu` / `armv7-unknown-linux-gnueabihf`。★armv7 资产存在性已确认（2026-10-18 实证 releases 页：https://github.com/astral-sh/python-build-standalone/releases）★——剩余未验证项只有"其 glibc 底线是否 ≤ 板子 2.31"（R-L22，一行 `objdump` 即可证伪） |
| **架构维度（新增概念，连带改动）** | ★现状★架构维度目前**只有 android 有**（`AppSpec.android_abis`、`runtime.resolve(..., abis=)`、`assemble._wheels_cache(platform, abi)` 按 abi 分目录）；`Pin.platform` 字段注释写死 `windows \| android`，linux 侧 `_wheels_cache("linux")` 是单目录、无 arch 子层。→ 加 linux 多架构须先决定：① 引入 `linux_abis` + `_wheels_cache(platform, arch)`（仿 android），或 ② `Pin` 加 `arch` 字段。★此项是 D-8 选 b/c 的前置，成本不计入 D-12★ |
| `assemble.py` | `_build_spk_linux`：与 windows 同构管线（libpython + stdlib pyc zip + deps.zip/散件 + applocal），差异点 = snapshot 解析、`python_dll` 键 → `libpython3.12.so.1.0`、`._pth` 文件名、wheels 平台 tag（`manylinux2014_x86_64` / `_aarch64` / armv7 见 D-12）、`setproctitle` 依赖追加（B.y） |
| `package.py` | `_package_linux`：staging 组装 §4.4 目录（launcher 补丁公钥 + spk + 侧车 + .service 模板）→ tar.gz `{name}-{version}-linux-{x86_64\|aarch64\|armv7l}.tar.gz`（★产物名带 arch★）；`_find_shell` 加 linux fallback（`_vendor/shell-linux/<arch>/`）。★双保险★：`_find_shell` 返回空 → `_package_linux` **硬失败拒出包**（return 非 0，文案指路 vendor/CI）——否则 ubuntu job 挂掉时会静默产出**无 launcher 的 linux tar.gz**（与 §5 vendor 行成对，见 R-L19） |
| `keybuild.py` | nt host + linux 目标 + 加密开启 → fail-fast（文案指路 WSL2/CI）；★并让 keylib 与 launcher 同容器编译以统一 glibc 基线（§4.2）★。多架构时 keylib 与 launcher **同交叉工具链**编译（`aarch64-linux-gnu-gcc` / `arm-linux-gnueabihf-gcc`），避免 glibc 底线被其中一方抬高。★armv7 基线口径★armv7 走 `ubuntu:20.04` 的 `arm-linux-gnueabihf`，sysroot glibc = **2.31**（manylinux2014 不提供 armhf 交叉链），与板子对齐；与 x86_64 的 2.17 为**两条并行基线**，勿混读 |
| `vendor.py` / `scripts/vendor.py` | 收录 CI 预编译 launcher ELF → `_vendor/shell-linux/<arch>/`；★档位修正★：原写"缺失容忍（与 shell exe 同策略）"自相矛盾——`scripts/vendor.py` L68-71 对 exe/dll/keylib_dll 是**硬失败 `return 2`**，"容忍"只存在于 android `.so` / keylib src / android 壳模板三处。建议 shell-linux 走"跳过 + 警告"档（同 android 壳模板），否则 ubuntu job 未产出时整个 release 断掉。★双保险★：打包期 `_find_shell` 为空 → `_package_linux` 硬失败拒出包（R-L19） |
| `applocal` | ★定位修正★：XDG 分支不在 applocal（`_env.py` 只校验 env）。applocal 侧仅两项：`set_process_title` 标题取应用名；XDG/目录归属 launcher（§3.1 步 4） |
| **新增** `shell-linux/` | launcher 工程：`src/main.c`（复用五模块：建议抽共享 `native/` 目录，或从 `shell-windows/src` 引用并固定方式）+ `build.sh` + 契约自测 harness（对齐 shell-windows 的 `--selftest-spk` 差分对拍模式，`tests/test_shell_contract.py`）。★CMakeLists 属新增而非"对齐"★——shell-windows 只有 `build.bat` + 手写 `cl` 命令 |
| CI `release.yml` + **`ci.yml`** | ubuntu job：manylinux2014 容器编译 launcher → artifact；windows job 下载并入 `_vendor` 后单次 wheel 构建（wheel 仍 py3-none-any，双平台二进制同包）。★补★`ci.yml` matrix 仅 `windows-latest`（L14），需加 ubuntu job，否则"契约测试三平台全绿"无 CI 承载。★工具链确认（非坑）★quay.io/pypa 的 manylinux2014 镜像自带并激活 devtoolset（gcc 10.x），"gcc 4.8"是 CentOS 7 系统 gcc 而非该镜像——搭建时 `gcc --version` ≥ 8 一行确认即可（见 R-L13）。★armv7（D-8 选 c 时，D-12 v5）★主路线 = **PyPI 交叉下载**（`pip download --platform manylinux2014_armv7l` / `--platform manylinux_2_31_armv7l`）→ `wheels/linux/armv7l/`，与 windows/aarch64 同管线；**fallback**（仅当审计发现某依赖无 armv7 wheel）：B1 Rust 系 → x86_64 主机 `maturin build --target armv7-unknown-linux-gnueabihf`（需 `rustup target add` + 指向 `arm-linux-gnueabihf-gcc` 的 linker，工具链钉版），分钟级；B2 纯 C 扩展 → QEMU binfmt（`docker run --privileged multiarch/qemu-user-static --reset -p yes`）+ `ubuntu:20.04` armv7 容器（sysroot glibc 2.31，与板子对齐）自建。QEMU 容器另兼 run 冒烟 |
| 测试 | golden linux 用例、契约测试三平台、注入 fail-closed 四路、可重现构建断言；★armv7★板子真机冒烟（阶段 5）与 QEMU 冒烟（CI）双轨 |

---

## 6. 实现计划（分阶段 + 估算）

| 阶段 | 内容 | 估算 | 闸门 |
|---|---|---|---|
| 0 生死验证 spike | WSL2：PBS linux 解包 → **确认含共享 `libpython3.12.so.1.0`**（R-L8，原漏）→ 最小 C 程序 `dlopen(RTLD_NOW\|RTLD_GLOBAL)` + POSIX `._pth` 隔离验证（命中基准三选一 + §4.1 三条可断言判据 + zipimport stdlib + import fastapi/uvicorn + **C 扩展能加载**）。★N2（D-8 选 c 时）★同一组断言顺带在 **QEMU armv7** 复跑一遍（+≤0.5 人日），提前暴露 armv7 特有的 getpath / PBS 布局差异，避免拖到阶段 5 | 0.5–1.5 人日（+≤0.5 若选 c） | ★硬闸：共享 libpython 缺失或隔离模式不成立 → 回退设计再评审★ |
| 1 launcher ELF | 五模块编译打通 → main 九步（含 2.5 完整性门）POSIX 化 → `MYAPP_*` env 契约 → watchdog 线程 + diag + 握手码打印 → `shell-linux` 构建工程 + 自测 harness。★建议拆为三个可验收子项：①main 骨架 ②watchdog+diag+env ③构建+harness★ | 3.5–6 人日（原 2.5–4 偏乐观：可复用仅五模块，`shell.cpp` 105KB 中编排层需重写） | WSL2 直跑 helloApp spk 起 Python、ready 出现；env 契约表逐项校验通过 |
| 2 pkapp 工具链 | fetch pin + assemble linux + package tar.gz + keylib fail-fast + 同容器编译 + vendor/CI ubuntu job 接线 | 2.5–3.5 人日 | Windows host 直跑 `build linux`（不加密）出包 |
| 3 applocal + 契约 | setproctitle 取应用名 + env 契约测试 + 契约/golden 测试三平台 + ELF 公钥补丁断言 | 1–1.5 人日 | 测试全绿（`ci.yml` ubuntu job 承载） |
| 4 冒烟验收 | WSL2 真 systemd 全链（§9 清单）+ 软链启动 + 升级切换 + 注入 fail-closed | 1–2 人日 | §9 验收全过 |
| **合计（x86_64 单架构）** | | **9–15 人日** | P1（delta 两件套、文档收尾）另计 +3–5 人日 |
| **5 armv7 板子线（D-8 选 c 时追加）** | **PBS armv7 三查（R-L22，首项且一票否决）**：资产存在 ✓ → `objdump` 实测 glibc 底线 ≤ 2.31 → 含共享 libpython；PBS `armv7-unknown-linux-gnueabihf` pin；launcher/keylib 交叉编译（`arm-linux-gnueabihf-gcc`，sysroot glibc 2.31）；linux 架构维度（§5 新增行）；wheel 按 D-12 v5 **PyPI 交叉下载为主**（依赖审计先行，B1/B2 仅 fallback）；QEMU 冒烟 + 板子真机验收 | **+1–2 人日** | armv7 板子上 `systemctl start` → ready → curl 矩阵通过；`pydantic>2` 的 armv7 wheel 板子实跑通过 |
| **合计（含 armv7）** | | **10.5–17.5 人日** | 含阶段 0 的 QEMU 复跑（+≤0.5）；阶段 5 因 D-12 v5（PyPI 交叉下载为主）自 +2–3 下调至 +1–2 人日 |

依赖顺序：阶段 0 → 1 → 2 → 3/4（3 与 4 部分可并行）；阶段 5 依赖 D-8 选 c，且**必须在阶段 2 之前完成"linux 架构维度"改造**，否则后期返工（pin / wheel 缓存目录 / 产物命名三处同时改）。

---

## 7. 决策点（待拍板）

| # | 决策 | 建议 | 理由摘要 |
|---|---|---|---|
| D-1 | launcher 形态 | **in-process 常驻 + watchdog 线程，单档**（不做 L0/L1/L2） | exec 消失型与 keylib 加密不兼容（解密后引导代码无合法入口）；systemd 只管进程死活，丢 hang 感知是行为倒退；launcher 必选后档位制失去存在理由 |
| D-2 | glibc 基线 | **x86_64 = manylinux2014（glibc 2.17）容器编译**；**armv7 = 2.31**（`ubuntu:20.04` 的 `arm-linux-gnueabihf` 交叉 sysroot）；musl 静态排除 | launcher 必须 dlopen（libpython + keylib），musl 静态二进制不支持 dlopen，glibc 静态有 NSS 限制；2.17 与 PBS gnu 底线对齐，覆盖 centos7+ 全部主流发行版。★两条基线并行口径（v4 补，消解读矛盾）★：2.17 只约束 **x86_64 容器编译**；armv7 线因 manylinux2014 **不提供 armhf 交叉链**，只能用 ubuntu:20.04 的 `arm-linux-gnueabihf`，其 sysroot glibc 即 **2.31**，与板子一致 ✓ —— 并非"2.17 兼容 2.31"，而是两条线各有基线，取 `max(交叉链 sysroot, PBS gnu 底线)` ≤ 板子 2.31。★v6★PBS armv7 资产**存在性已确认**；但"PBS gnu 底线 ≤ 2.31"仍是**未验证的断言**（PBS Linux 构建环境若为 Ubuntu 22.04 = glibc 2.35，则 > 2.31，armv7 线不成立）→ 见 R-L22，必须 objdump 实测后再落 D-8 选 c |
| D-3 | keylib 构建路径 | **官方路径 = WSL2 / CI ubuntu**；Windows host 加密 fail-fast 指路；不做 zig cc 交叉（v1） | pkapp 纯 Python 天然跨平台；CI 反正要 ubuntu job；交叉工具链是新增依赖+测试面，收益不值 |
| D-4 | 侧车合同 | **沿用 Q7**：侧车与 ELF 同级（部署目录根） | 与 Windows"exe 所在目录"语义逐字一致，零成本 |
| D-5 | 路径钉死载体 | **POSIX `._pth`**（暂定 `libpython3.12.so.1.0._pth`），替代 v8 铺 env 路线 | 隔离模式对齐 P0 R1-9，env 注入面三端同步封死；v8 已预留"未来统一再评估"口径，即现在 |
| **D-6** | 冻结感知 | **建议：`.service` 加 `WatchdogSec=` + watchdog 线程 `sd_notify("WATCHDOG=1")`**（不采纳则文档明示"进程级冻结不在监督范围"） | in-process watchdog 随进程一并冻结，无法感知 `SIGSTOP`/freeze（Android L2 正因如此做成进程外）。sd_notify 走 NOTIFY_SOCKET 协议、手写 ~30 行、零额外进程，是唯一低成本覆盖路径 |
| **D-7**（**建议与 D-9 合并拍板**） | 解包区与运行身份 | **三选项**：① 部署目录只读 + 预解包（★提权细节★：`ExecStartPre` **默认仍以 `User=` 运行**，要由 root/部署账号解包须写 `ExecStartPre=+<cmd>`——`+` 前缀 = 全特权执行——完成后再降权；拍板①时须把该行写进 `.service` 模板）；② 部署目录可写（运行账号可写）；③ ★新增★`_runtime/` 迁 `StateDirectory`（`/var/lib/myapp/runtime-<ver>/`），部署目录保持只读 | 与 BOOTSTRAP §9"部署目录 owner 非运行账号"冲突（见 §4.4 / R-L11）。★选项③核对结论★：指纹记账/升级覆盖**不假设**`_runtime` 与 spk 同目录——`runtime.version`（`shell.cpp` L1482 写入）、`manifest`（L2202/L2395）、`python_dll`（L1466 加载）、受保护树枚举根（L2123）全部在 `_runtime` 内部自洽；真正的耦合只有 `g_runtime = join_path(g_install, "_runtime")`（L319）与 staging 同目录（L487）两处硬编码，解开成本很低。★但代价★：受保护树整体迁入**运行账号可写区**，P0"校验对象只读"的保证被削弱（R-L18）——选项③解决的是"首启可写"，未解决"校验对象不可被改写"，需与 D-9 一并定 |
| **D-8** | 架构矩阵 | **三选项**：a) 仅 x86_64；b) +aarch64；**c) +armv7 板子线（★真实部署目标驱动，建议★）** | 已确认真实目标为 **glibc 2.31 的 armv7 开发板**：板子 2.31 → piwheels 双现役线（Bookworm 2.36 / Trixie 2.41）全部不适用 → C 路线（piwheels 现成 wheel）出局，只剩 A/B（见 D-12）。D-2 的 2.17 基线 ≤ 2.31 ✓ 无需改。aarch64 次之（ARM 服务器/信创，PBS 有 `aarch64-unknown-linux-gnu`，tag `manylinux2014_aarch64`）；越晚加，pin / wheel 缓存目录 / 产物命名三处改动面越大 |
| **D-9** | 数据/缓存目录 | **待拍板**：XDG（`~/.local/share`、`~/.cache`，用户级）vs systemd `StateDirectory/CacheDirectory`（系统级） | 影响 `User=` 下 HOME 语义、权限分离与多实例隔离；系统服务场景 `/var/lib` 更常规且由 systemd 保证属主。★与 D-7 是同一自由度★——选 StateDirectory 时 D-7 选项③几乎顺带成立，建议合并拍板 |
| **D-10** | 日志与握手码去向 | **待拍板**：仅文件 / 仅 journald / 双写（tee 保留原 fd） | 步骤 5 `dup2` 后 stdout 不再进 journald，而 §0/§3.2/§9 多处写"打印到 journal"——自相矛盾，须定其一并给运维取值命令 |
| **D-11** | 单实例冲突退出码 | **建议：flock 失败短重试（≤ `RestartSec`）**；"已有实例存活"走 `SuccessExitStatus=75`（**`EX_TEMPFAIL=75`，拍板即定值**） | 直接 exit 非 0 会被 systemd 判失败再重启，形成启动抖动（见 §3.2 / R-L14）。约定：75 = 已有实例存活（不算失败）、非 0 且 ≠75 = 真实故障（触发重启） |
| **D-12** | armv7 wheel 策略 | **★v5 改判：主路线 = PyPI 交叉下载（零自建）；B1/B2 自建降为 fallback★**。主路线走既有 per-platform 下载管线：`pip download --platform manylinux2014_armv7l`（pydantic-core 等，glibc 2.17）+ `--platform manylinux_2_31_armv7l`（cryptography abi3，glibc 2.31）→ `wheels/linux/armv7l/`。fallback：B1 = x86_64 主机 `maturin` + armv7 交叉链；B2 = QEMU binfmt + `ubuntu:20.04` armv7 容器（另兼冒烟）——仅当依赖审计发现某包无 armv7 wheel 时启用 | **2026-10 PyPI 实证（files 页）**：`pydantic_core-2.20.1-cp312-cp312-manylinux_2_17_armv7l.manylinux2014_armv7l.whl` 存在（cp310–cp313 全线有 armv7l）；`cryptography-50.0.2-cp311-abi3-manylinux_2_31_armv7l.whl` 存在（abi3 覆盖 cp312；2.31 底线恰 = 板子，边界达标）。此前"PyPI 无 armv7 轮子 ⇒ 必须自建"的判断过时。仍成立的旧结论：C（piwheels 现役线 Bookworm 2.36 / Trixie 2.41）对板子 2.31 出局；A（`pydantic<2`）因 v1 维护模式否决。风险面见 R-L20（wheel 覆盖审计 + fallback 触发条件） |

> D-5 依赖阶段 0 硬闸实证；若实证失败（dlopen 嵌入下 `._pth` 命中规则不成立），回退方案 = launcher `setenv` 铺路径 + 文档明示 Linux 侧 env 注入面由部署权限分离（BOOTSTRAP_INTEGRITY_PLAN §9）兜底——属降级口径，需重新评审。
>
> ★第一硬闸其实是 D-5 的前置★：PBS linux 是否含**共享** `libpython3.12.so.1.0`（R-L8）。共享库缺失则 dlopen 路线整体不成立，D-5 无需再议。

---

## 8. 风险登记

| # | 风险 | 等级 | 对策 |
|---|---|---|---|
| R-L1 | POSIX `._pth` 在 dlopen 嵌入下的命中规则与隔离行为未实证 | 高 | 阶段 0 硬闸（0.5 天）；失败走 D-5 回退口径 |
| R-L2 | launcher 静态链接诉求与 dlopen 冲突 | 已闭合 | D-2：动态链接 + 2.17 容器编译，不追静态 |
| R-L3 | keylib 构建机 glibc > 部署目标 → 目标机 dlopen 失败 | 中 | 官方路径下 keylib 与 launcher **同容器编译**（§4.2），而非仅文档约束；构建文档给 WSL2 发行版建议 |
| R-L4 | 本机验证依赖 WSL2 真 systemd（`.service` 验收） | 中 | `wsl.conf` 开 systemd；不行则 VM；headless curl 矩阵不强依赖 systemd |
| R-L5 | PBS linux 布局差异（bin/lib/lib64、stripped 版内容）与 windows 假设不符 | 低 | 阶段 0 实测布局回填 assemble 拷贝规则（多架构时逐架构回填） |
| R-L6 | CI 容器 gcc/clang 版本漂移触发 `-Werror` 新告警 | 低 | 容器内锁定工具链版本（与 keylib android NDK clang 锁版同思路） |
| R-L7 | 握手码 UX 降级（无自动导航，首启 URL 靠 journal/日志文件） | 低 | 文档写明首启获取方式（随 D-10 落定）；launcher 打印格式与 Windows 导航 URL 逐字一致 |
| **R-L8** | PBS linux `install_only` 不含共享 `libpython3.12.so.1.0` → dlopen 路线整体不成立 | **低**（原记"高"，★v3 下调★） | ★下调依据★PBS **gnu** 构建是 `--enable-shared`（官方文档"gnu builds 能加载编译扩展"即共享 libpython 的同义表述），只有 musl `+static` 变体无共享库；本方案 D-2 已排除 musl。验证成本≈0，仍保留为阶段 0 第一项（先证伪再往下走） |
| **R-L9** | 公钥锚点补丁在 ELF 上失效：`-fPIC`/`-O2`/strip 后 64-hex 常量段不再唯一或连续可定位 | 中 | 编译期固定该常量为独立符号；扩 `pkapp/tests/test_release_vendor.py` 加 ELF 用例（与现有 exe 对拍同形） |
| **R-L10** | `/usr/local/bin/myapp` 软链导致 `argv[0]` 与真实路径不符，spk/侧车/解包区定位错误 | 中 | 一律 `realpath("/proc/self/exe")` 解析；验收含"经软链启动"用例 |
| **R-L11** | 部署目录只读（BOOTSTRAP §9 权限分离）与首启解包写 `_runtime/` 冲突 | 中 | D-7 拍板；未决前不得开工阶段 2 |
| **R-L12** | in-process watchdog 无法感知进程级冻结（`SIGSTOP`/freeze），原 §9.3 用 SIGSTOP 验证不成立 | 中 | 验收改应用层挂起/死锁注入；要覆盖冻结走 D-6（systemd `WatchdogSec` + sd_notify） |
| **R-L13** | launcher/keylib 用 `-std=c17`，构建容器 gcc 需 ≥ 8 | **已闭合**（★v3 修正★） | ★表述修正★原写"manylinux2014 默认 gcc 4.8"不准——那是 CentOS 7 **系统** gcc；quay.io/pypa 的 manylinux2014 镜像自带并激活 devtoolset（gcc 10.x）。降级为搭建时一行确认：容器内 `gcc --version` ≥ 8 |
| **R-L14** | flock 失败即退出非 0 → systemd 判失败再重启，启动抖动 | 低 | D-11：短重试或 `SuccessExitStatus` |
| **R-L15** | 架构矩阵未定（文档仅 x86_64），后期加 aarch64/armv7 的改动面 | 低 | D-8 明确范围；命名/CI/wheel tag 一次性预留 |
| **R-L16** | **armv7 板子线**（D-8 选 c）：交叉工具链、QEMU 构建、板子真机验证三处均无先例 | 中 | 阶段 5 单列（v5：+1–2 人日）；launcher/keylib/PBS 三件同交叉链编译；CI 加 QEMU binfmt job，板子真机冒烟另列验收 |
| **R-L17** | **linux 缺架构维度**：现只有 android 有 `abis`；`Pin.platform` 注释写死 `windows \| android`，`_wheels_cache("linux")` 无 arch 子层 | 中 | D-8 选 b/c 的**前置**：先定 `linux_abis` + `_wheels_cache(platform, arch)`（仿 android）还是 `Pin` 加 `arch` 字段。必须在阶段 2 前完成，否则 pin/wheel 缓存/产物命名三处同时返工 |
| **R-L18** | D-7 选项③（`_runtime` 迁 StateDirectory）把受保护树移入**运行账号可写区**，P0"校验对象只读"保证被削弱 | 中 | 与 D-9 合并拍板；若采纳，须写明残余风险并靠"解包后 launcher 校验 + 运行期降权/只读挂载"兜底，或退回选项①（部署账号预解包） |
| **R-L19** | vendor 走"跳过+警告"档后，ubuntu job 挂掉→ CI 静默产出**无 launcher 的 linux tar.gz** | 中 | 双保险：打包期 `_find_shell` 为空 → `_package_linux` **硬失败拒出包**（文案指路 vendor/CI）；wheel 内 `_vendor/shell-linux/<arch>` 缺失同理 |
| **R-L20** | **依赖集 armv7 wheel 覆盖缺口**（主路线 = PyPI 交叉下载，逐包核对）：① pydantic-core 与 pydantic **版本钉死联动**——选定 pydantic 所要求的 pydantic-core 版本必须有 armv7l wheel（2.20.1 已实证）；② abi3 tag 匹配（cryptography `cp311-abi3` 覆盖 cp312 ✓）；③ cryptography 底线 glibc **2.31 恰 = 板子**——换更低 glibc 的板子即无现成轮子 | 中 | 依赖审计先行（阶段 5 首项）；缺口包才启用 fallback 自建：B1 = x86_64 主机 `maturin` 交叉（选版优先 piwheels 已原生构建过的版本 + rust 工具链钉版）；构建后**QEMU/板子实跑 import 验证**（不放过"构建成功但加载失败"）；产物入 `wheels/linux/armv7l/` |
| **R-L21** | 两条 glibc 基线（x86_64 2.17 / armv7 2.31）被混读，误以为 2.17 产物可覆盖板子 | 低 | D-2 与 §5 keybuild 行已写明"并行两条基线"；产物名带 arch（`linux-x86_64` / `linux-armv7l`）从命名上杜绝混用 |
| **R-L22** | **PBS armv7 资产的 glibc 底线 > 板子 2.31**（资产存在性已确认 ✓，但构建环境未知：Ubuntu 20.04 = 2.31 边界达标，22.04 = 2.35 即超标）→ 板子 dlopen/run 直接失败 | **中（v6：由"资产可能不存在"收窄为此一项）** | 阶段 5 **首项**三查（成本≈0，须在"选 c"落地前完成）：① 资产存在 ✓（releases 页已实证）；② `objdump -T libpython3.12.so.1.0 \| grep -o 'GLIBC_2\.[0-9]*' \| sort -V \| tail -1` → 实测最高需求 ≤ 2.31；③ 含共享 `libpython3.12.so.1.0`（R-L8 的 armv7 版）。超标则 armv7 线需回退（自建 CPython / 板子系统 Python / 换板子），并重新评审 D-8 |

---

## 9. 验收标准

1. **阶段 0 硬闸**：① PBS linux 含共享 `libpython3.12.so.1.0`（R-L8，等级已下调为低，仍先证伪）；② dlopen 嵌入 + POSIX `._pth` 隔离模式成立，命中基准实测确定；③ `sys.flags.isolated==1` 且 `PYTHONPATH` 注入被忽略；④ **C 扩展可加载**——与 §3.1 步 6 同口径，即 `dlopen(..., RTLD_NOW|RTLD_GLOBAL)` 生效的断言（✓ 措辞已一致）；
2. **全链冒烟**（WSL2 真 systemd）：`build linux → package → 解包 → systemctl start → ready` → curl 矩阵（302→/login、cookie 登录、200、401）与 Windows 逐位一致；★补★**经 `/usr/local/bin/myapp` 软链启动**同样通过（R-L10）；
3. **心跳监督**：`kill -9` → systemd 拉起；★死锁注入只能用应用层挂起/死锁（GIL 死锁、锁死、死循环不 touch ready）★——**不得用 `SIGSTOP`**（watchdog 随之冻结，R-L12）；launcher 30s 内判死退出非零，见 diag，systemd 重启恢复；
4. **注入 fail-closed 四路**：篡改 `_core.py` 同形文件 / 丢 `.pth` / 伪造 pyc / 改 `._pth` → 拒启 + diag（★引用校正★：BOOTSTRAP_INTEGRITY_PLAN 无 §8.1 小节，对应 **§8 验收标准第 1 条**，L202）；
5. **升级**：新版本目录解包 + `ln -sfn` 秒切（unit 变化时 `daemon-reload`），data 完好、`_runtime` 指纹记账推进；
6. **进程标识**：ps / top / systemctl 三处显示应用名（★非 `myapp` 命名的应用同样成立★，见 §4.5）；
7. **Windows host 加密 fail-fast**：报错文案正确指向 WSL2/CI；
8. **可重现构建**：deps.zip + applocal 散件 pyc 哈希跨构建一致（D4/★R1-7★ 口径）；
9. **env 契约**：launcher 铺出的 `MYAPP_*` 与 §3.1 表逐项对齐（必填项缺失 → fail-fast 而非运行中 `ContractError`）；
10. **ELF 公钥补丁断言**：改公钥后 ELF 内恰好一处被改写，验签随之切换（R-L9）；
11. **契约测试三平台全绿** + `ci.yml`/`release.yml` ubuntu job 双绿 + wheel 内 `_vendor/shell-linux/<arch>` 就位（重装 pkapp 即可用，零编译壳哲学延续）；
12. **★armv7 板子线（D-8 选 c）★**：glibc 2.31 板子上 `systemctl start` → ready → curl 矩阵通过；交叉编译产物与 QEMU 冒烟双绿；wheel 按 D-12 v5 落地（PyPI 交叉下载为主）——`pydantic>2` 链路的 `pydantic-core`/`cryptography` armv7 wheel 必须板子实跑 import 通过（R-L20），fallback 自建仅审计发现缺口时启用；
13. **无 launcher 不产包**：`_vendor/shell-linux/<arch>` 缺失时 `pkapp package linux` 硬失败拒出包（R-L19），不得产出空壳 tar.gz。

---

## 10. v2 评审修订记录（2026-10-17，对照代码核对）

### 10.1 修正的事实性偏差

| 原表述 | 修正 |
|---|---|
| 五模块"零 Windows 依赖（已核实 include 清单）" | `spk.c` L11-13 有 `#ifdef _WIN32`/`<windows.h>`（L36-38 有 POSIX `#else`），可编译但措辞不实 |
| 五个模块可移植归因于 Q6 | Q6 原文只给"验哈希"单模块立先例；五模块可移植是代码事实 |
| `package.py` `_patch_shell_pub` | 实为 `_patch_shell_pubkey`（L190/调用 L310） |
| "`linux_setproctitle=True` 默认装入" | 字段默认 True 但无消费代码；applocal 侧硬编码 `set_process_title("myapp")` |
| applocal 需 XDG 分支 | 目录决策权在壳；`_env.py` 只校验必填 env |
| vendor"缺失容忍（与 shell exe 同策略）" | shell exe 实为硬失败 `return 2`，两者矛盾 |
| keylib fail-fast 已存在 | 现状未实现（`assemble.py` L1112-1115 按构建机选 host） |
| "purge 事实经启动参数传给 applocal" | Windows 实为环境变量 `MYAPP_INTEGRITY_PURGE`（`shell.cpp` L2399-2406） |
| BOOTSTRAP §4.6 D5 / §8.1 | D5 定义在 §5 L160；无 §8.1 小节（对应 §8 验收第 1 条 L202） |
| v8 §5.7 / §5.8 引用 | 章节号在（L365/L366）但正文为空（"同 v7.3"），实质内容在 L79/L87/L113/L389 |

### 10.2 补的设计漏洞

共享 libpython 前提（R-L8）、`._pth` 命中基准三选一 + 可断言判据、`dlopen` 需 `RTLD_GLOBAL`、软链路径解析（R-L10）、解包区 × 权限分离冲突（R-L11/D-7）、in-process watchdog 冻结盲区（R-L12/D-6）、journald 与 dup2 冲突（D-10）、flock × systemd 抖动（R-L14/D-11）、架构矩阵（D-8）、数据目录（D-9）、`MYAPP_*` env 契约表、阶段 1 估算上调（8–13 → 9–15 人日）。

### 10.3 拍板前不得开工的项

- **R-L8 / R-L11 / D-7**：共享 libpython（现判为低风险但仍先证伪）与解包区可写性任一不成立，方案需重新评审；
- **D-1 与 D-6 需一并看**：只做 in-process 就等于放弃冻结感知，须显式接受或加 `WatchdogSec`；
- **D-8 选 b/c 前先解 R-L17**：linux 架构维度未立，pin / wheel 缓存 / 产物命名三处会同时返工。

### 10.4 v3 修订记录（2026-10-18 二轮评审）

| 项 | 处理 |
|---|---|
| **A armv7 板子线整条缺失（阻塞）** | D-8 改三选项（c = +armv7，真实目标驱动）；新增 **D-12** armv7 wheel 策略（piwheels Bookworm 2.36/Trixie 2.41 对板子 glibc 2.31 全不适用 → C 出局）；阶段 5 单列 +2–3 人日；§5 补 PBS armv7 pin、交叉编译、QEMU job；§9 补板子真机验收；D-2 确认 2.17 ≤ 2.31 ✓ |
| **B1 R-L13 表述不准** | 改"已闭合"：manylinux2014 镜像自带 devtoolset（gcc 10.x），"gcc 4.8"属 CentOS 7 系统 gcc；降级为 `gcc --version` ≥ 8 一行确认 |
| **B2 R-L8 等级** | 高 → **低**（PBS gnu 构建 `--enable-shared`，仅 musl `+static` 无共享库，D-2 已排除 musl）；仍保留为阶段 0 第一项先证伪 |
| **C1 D-7 第三选项** | 补（`_runtime` 迁 StateDirectory）+ 核对结论：指纹记账/升级覆盖**不假设**与 spk 同目录（`shell.cpp` L319/L487/L1482/L2123），解开成本低；代价＝受保护树变可写（R-L18）；标注与 D-9 合并拍板 |
| **C2 vendor 双保险** | vendor 走"跳过+警告" + `_package_linux` 中 `_find_shell` 为空**硬失败拒出包**（R-L19 + §9.13） |
| **D1 D-11 退出码** | 定值 `EX_TEMPFAIL=75`（已有实例存活不计失败；其余非 0 触发重启） |
| **D2 §9.1④ 措辞** | 与 §3.1 步 6 同口径（`RTLD_NOW\|RTLD_GLOBAL` 生效断言）✓ |
| **连带发现 R-L17** | linux **缺架构维度**：现只有 android 有 `abis`，`Pin.platform` 注释写死 `windows \| android`、`_wheels_cache("linux")` 无 arch 子层 → D-8 选 b/c 的**前置**，须在阶段 2 前完成 |

### 10.5 v4 修订记录（2026-10-18 三轮评审）

| 项 | 处理 |
|---|---|
| **M1 armv7 交叉链 glibc 基线未写（唯一实质矛盾）** | D-2 与 §5 keybuild 行均补明：**两条并行基线**——x86_64 = 2.17（manylinux2014 容器）；**armv7 = 2.31**（`ubuntu:20.04` 的 `arm-linux-gnueabihf` 交叉 sysroot，manylinux2014 不提供 armhf 交叉链），与板子对齐；明确"不是 2.17 兼容 2.31，而是两条线各有基线"（新增 R-L21 防混读；产物名带 arch 从命名上杜绝） |
| **M2 D-12 A 路线的长期债务** | **改判：A 对 pydantic 否决，B 由"可选"变"必经"**。理由入表：pydantic v1 已进维护模式、无积极开发、安全更新面收窄，项目要求 `pydantic>2` ⇒ 必须自建 `pydantic-core`。A 降为"削减 B 工作量"的辅助手段 |
| **M3 Rust 轮子不能放 QEMU 里原生编译** | D-12 拆 **B1/B2 两通道**：B1 Rust 系（`pydantic-core`/`cryptography`）走 x86_64 主机 `maturin --target armv7-unknown-linux-gnueabihf`（分钟级）；B2 纯 C 扩展走 QEMU binfmt + `ubuntu:20.04` armv7 容器，QEMU 另兼冒烟。§5 CI 行、阶段 5、§9.12 同步；新增 **R-L20**（rustup target / linker / maturin 配置错配是 dlopen 期才炸，构建后须 QEMU + 板子实跑 import） |
| **N1 `ExecStartPre` 提权细节** | D-7 选项①补明：`ExecStartPre` 默认仍以 `User=` 运行，要由部署/root 身份预解包须写 **`ExecStartPre=+<cmd>`**（`+` = 全特权）后再降权；拍板①时须落进 `.service` 模板 |
| **N2 阶段 0 顺带跑 armv7** | 阶段 0 加"D-8 选 c 时同一组断言在 QEMU armv7 复跑（+≤0.5 人日）"，提前暴露 armv7 的 getpath / PBS 布局差异；合计含 armv7 调整为 **11.5–18.5 人日** |

### 10.6 v6 修订记录（2026-10-18：PBS armv7 资产实证）

| 项 | 处理 |
|---|---|
| **PBS armv7 现成构建（用户实证 releases 页）** | 评审提出的 S1 **第一项闭合**：PBS 提供 armv7 现成构建（https://github.com/astral-sh/python-build-standalone/releases），§5 toolchain 行与 D-2 已标注"存在性已确认" |
| **S1 收窄为单一剩余项** | 新增 **R-L22（中）**：该构建的 **glibc 底线是否 ≤ 板子 2.31**（PBS Linux 构建环境若为 Ubuntu 22.04 = 2.35 则超标）。验证 = 解包后 `objdump -T libpython3.12.so.1.0 \| grep -o 'GLIBC_2\.[0-9]*' \| sort -V \| tail -1`；已列为**阶段 5 首项、一票否决**，超标则 armv7 线回退并重新评审 D-8 |
| **连带** | 阶段 5 内容前置"PBS armv7 三查"（存在 ✓ / glibc 底线 / 含共享 libpython）；D-2 并行基线表述加注"PBS gnu 底线 ≤ 2.31 仍是未验证断言" |
