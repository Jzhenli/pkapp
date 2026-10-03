# PACKAGER_SPEC.md — 协议 B 事实源（packager ⇄ 壳）
**版本**：v0.1（由 `pkapp打包方案v8.md` §3 / §10 + §〇 v8.1 复核补丁落地）
**地位**：**runtime.spk 的格式、manifest 键位、验证规则、golden test 断言的唯一事实源**。
**核心不变量**：packager 产出**单一同构 `_runtime` 布局**（无任何平台条件分支）；平台分叉只允许出现在壳层。

---
## 1. 产物布局（三端同构，packager 单管线产出）
```
_runtime/
├── libpython*.(dll|so)     ← 解释器本体，文件名由 manifest.python_dll 声明
├── python312.zip           ← 标准库（zipimport 直读）★文件名派生自 python_dll★
├── DLLs/                   ← 扩展模块 .pyd + 传递原生依赖（见 B.s）
├── python312._pth          ← Windows 目标必产；★必须与 python_dll 同目录，内容派生★
├── site-packages/          ← 全部第三方依赖（applocal 为普通一员）
├── app/                    ← 用户后端代码（import 根）★packager 永不写入★
├── dist/                   ← Vue 产物 ★恒存在★
└── manifest                ← 包内自述（键位见 §2）
```
**同构约束**：`app/` 与 `dist/` 之外的任何产出都不得含平台条件分支；Android 的 so 迁出至 APK `lib/<abi>/` 发生在**打包 APK 阶段**（APK 装配），不属于 packager 管线分支。

---
## 2. manifest 键位定稿
```ini
format_version   = 1            # 壳校验：未知版本拒绝并提示需新壳
app_version      = 1.4.2
min_app_version  = 1.2.0        # ★v8.1 V9★防回滚；低于此值拒绝加载（必填非空）
applocal_version = 0.1.0
python_dll       = python312.dll # ★壳据此 LoadLibrary，禁止硬编码；必填非空★
runtime_hash     = sha256:...
app_hash         = sha256:...
dist_hash        = sha256:...
spk_hash         = sha256:...
signature        = base64:...    # 发布私钥对上述全部字段签名（或 minisign 独立 .sig）
```
**校验顺序（壳侧）**：`format_version` → 验签 → **版本单调性**（`app_version ≥ min_app_version` 且 ≥ 本地已安装最高版本，除非 AppSpec 显式允许降级）→ `spk_hash` → 解压 → 树 hash 比对。任一不过 → diag.json 渲染错误页（详见 `SHELL_PROTOCOL.md` §9）。

> 为什么必须补 `min_app_version`：U 盘 / 局域网是本方案的主投递路径，"有签名"证明不了"不是旧包"。

---
## 3. 验签规则
- 无论全量 / delta、无论 U 盘 / 局域网 / HTTPS，**解压前一律先验签**（Linux 例外见方案 §5.7）。
- 指纹保证"解压的与拿到的一致"，签名保证"拿到的来自发布者"，版本单调性保证"不是旧包"。
- 私钥只存在于发布环境；公钥内置于壳。格式待决策（M0 D1）：**minisign / signify**（见 §9 待决策）。

---
## 4. 目录契约四铁律 + 指纹三规则
**四铁律**：① 只读区随时可整删重建，严禁覆盖式解压；② 用户数据绝不进只读区；③ 路径钉死为展开后绝对路径（`_pth` / PyConfig）；④ Android so 走 `lib/<abi>/`。
**指纹三规则**：
```
① 原子写入（tmp + rename）；
② 缺失/损坏 = 全量重建；
③ ★记账时机 = LoadLibrary 成功之后（而非 rename 完成后）
   ——只有真正加载成功的展开区才被记账，杜绝"半状态被指纹洗白"。
```

---
## 5. 增补条款
### B.x Windows 目标必产 `_pth`（★v8.1 V13：派生，不再写死★）
```
令 STEM = python_dll 去掉扩展名（python312.dll → python312；python313.dll → python313）
文件名：_runtime/<STEM>._pth   —— 必须与 python_dll 同目录
内容四行：
    <STEM>.zip        ← 标准库 zip（来源为松散文件时由 packager 打成此名）
    DLLs              ← 扩展模块 + 传递原生依赖
    site-packages
    import site
app/ 不得写入 _pth——由 applocal bootstrap 步骤 1 运行时追加。
```
> 原 v8.0 文本写死 `python312.zip`，与 B.z③"文件名随 python_dll 走"自相矛盾，会把"3.13 升级演练"必炸，故修订。

### B.y Linux 目标默认装入 `setproctitle`
可选依赖；bootstrap 步骤 0 探测调用，探测不到静默跳过。

### B.z golden test 断言（★v8.1 增补 ④⑤★；★v0.3 增补 ⑥★）
```
① _pth 存在且逐字节等于规范内容（按 B.x 派生后的期望值比对）；
② manifest.python_dll 与包内实际 DLL 文件名一致；
③ _pth 文件名 = python_dll 去扩展名 + ._pth（版本号一致性）；
④ _pth 第一行 = 包内实际存在的标准库 zip 文件名（存在性检查，非字符串假设）；
⑤ 包内含 DLLs/，且每个 .pyd 的传递依赖均在目录内（依赖闭包完整，见 B.s）；
⑥ 包内含 certifi（B.v 出网信任链硬约束）——packager 恒装入（无论 AppSpec 是否声明），缺失即构建失败。
```
**附加**：同一输入两次构建 → spk 字节级可复现（见 B.u）。

### B.w manifest 键位定稿
含 `python_dll`（§2）与 `min_app_version`；packager 校验二者必填非空。

### B.s（★v8.1 V5★）Windows 原生依赖闭包
packager 对每个 `.pyd` 计算**传递依赖闭包**（PE import table 遍历，或 wheel 侧声明 `native_deps` 白名单），全部纳入 `DLLs/`。
最小样例：`_ssl.pyd → libssl-*.dll / libcrypto-*.dll`（缺一则在联网功能上 ImportError）。
**构建期自检**：闭包不完整 → **构建失败**，不得留给真机报错。

### B.t（★v8.1 V4★）`_pth` 放置与打包禁令
依据 CPython 3.12 `Modules/getpath.py`：
```
_pth 查找顺序 = [library(python3XX.dll 全路径, 去扩展名+._pth),
                 executable, real_executable]  —— 命中即止
命中后：isolated=1 / use_environment=0 / site_import=0(除 import site 行) / safe_path=1
每行路径按 joinpath(pth_dir, line) 解析
```
⇒ **禁令**：
1. CPython 产物必须是**含 `python3XX.dll` 的共享构建**（`Py_ENABLE_SHARED`）；静态 libpython 时 `library` 为空，将退回按 EXE 目录查找。
2. **安装目录（`MyApp\`）严禁出现 `<EXE-stem>._pth`**——展开区缺失时会被 fallback 命中，且其相对行按安装目录解析，会静默指向不存在的 DLLs/site-packages。
3. packager 与 `pkapp doctor` **均须断言**以上两项。

### B.u（★v8.1 V12★）pyc 可复现性
统一使用 `--invalidation-mode checked-hash` + 固化 `SOURCE_DATE_EPOCH`；否则源 mtime 被烧进 pyc → spk hash 每次不同 → golden test 随机红。

**★v0.5★ 标准库 zip 必须预编译 pyc 一并打入（★启动优化★）**：`<STEM>.zip` 打包时由快照解释器对全部 `.py` 预编译 checked-hash pyc，以**扁平 `<dir>/<mod>.pyc` 布局**写入（zipimport 在 zip 内只查扁平 `.pyc` 条目、不认 `__pycache__/` 目录；`.pyc` 优先于同名 `.py`）。缺 pyc 时每次启动都从源码重编译整个被引标准库——Windows 实测每次启动多花 ~2s（`import applocal` 2.7s → 0.2s）。compileall 走独立暂存副本，不改快照本体。

### B.v（★v8.1 V10★）出网信任链
默认装入 `certifi` wheel；出网统一 `ssl.create_default_context(cafile=certifi.where())`（在 applocal 内部使用，**不新增冻结 API**）。缺失则 HTTPS 更新链必然失败。

---
## 6. spk 封装规则
```
格式：zip，STORED（无压缩）—— rationale：展开区文件可被原样 mmap/加载，且避免解压器差异
       ⚠ Android 侧 .so 提取仍受 16KB 对齐约束（R23），由 APK 装配阶段负责
顺序：文件路径列表按 UTF-8 字节序排序（可复现）
路径：相对 _runtime/ 的路径，分隔符统一 '/'
禁止：绝对路径、'..'、目录项重复写入
★v0.3 spk_hash 定义（实现条款化）★：
    对 spk 内除 manifest 外全部条目（按包内顺序）取
      f"{path}\0{sha256(content).hexdigest()}\n"
    拼接后取 sha256 → manifest.spk_hash = "sha256:<hex>"。
    壳验签流程：读 manifest → 验签（覆盖除 signature 行外正文）→ 同法重算 spk_hash
    比对 → 解压 → 树 hash 比对（§2 校验顺序不变）。
★v0.3 pyc 可复现实现注记★：pyc 的 co_filename 一律为包内相对路径（compile dfile=rel）——
    绝对 staging 路径会烧进 pyc 破坏 G1；checked-hash 头只含源 hash + 大小（B.u）。
```

---
## 7. 升级与 delta
- **全量包即升级包**；分层账本：`app/`、`dist/` 可 delta（M3），`site-packages`（含 applocal）与运行时**永远全量**。
- **壳二进制永不热升级**——由 `manifest.python_dll` 键保障该铁律跨 CPython 版本成立。
- `format_version` 未知一律拒绝。
- **coexist 默认关闭**（AppSpec 开关）：三条条款 + 竞态未验证登记。

---
## 8. golden test 与 CI 断言清单
```
G1  spk 字节级可复现（同输入跑两次，hash 一致）
G2  manifest 键位齐全：python_dll / min_app_version / *_hash / signature 非空
G3  B.z 五断言（①–⑤）
G4  spk_hash 与实际字节一致；篡改任一字节 → 验签/指纹必须失败（负向用例）
G5  构造 app_version < min_app_version 的包 → 必须被拒（负向用例）
G6  安装目录扫描：不存在 <EXE-stem>._pth（负向用例）
G7  Windows 原生依赖闭包完整（负向：故意删掉 libcrypto → 构建失败）
G8  Android：所有 native 产物 ELF 段满足 16KB 对齐 + zipalign -P 16 校验
G9  fingerprints 三规则：tmp+rename 原子写、损坏=全量重建、记账时机在 LoadLibrary 之后
G10 ★V15★ 安装目录洁净断言：不得含 *.py / 包目录 / DLLs / <EXE-stem>._pth
    （Windows 会把可执行文件目录追加进 sys.path，见 SHELL_PROTOCOL §2.1）
G11 Windows 目标实跑断言（M0 D2 起的 CI 门槛）：
    用生成的 _runtime 跑通 `python3XX.exe -I -c "import ssl, asyncio, json"`，
    且 sys.path 首个四项等于 B.x 派生值 + 安装目录（顺序按 SHELL_PROTOCOL §2.1 ③）
```

---
## 9. M0 D1/D2 实测已定案项（协议第一份实证）
| 原待定项 | 实测结论 | 证据 |
|---|---|---|
| 标准库形态 | **松散 `Lib/`，必须由 packager 打成 `<STEM>.zip`**——`python312.zip` 不是 PBS 自带产物，B.x 首行依赖这一步 | `pkapp/tools/make_runtime_proto.py` 实测：532 个文件 → `python312.zip` |
| `_pth` 是否预置 | **不带**，必须由 packager 生成（内容与命名均派生自 `python_dll`） | 同上 |
| 依赖闭包实际清单（B.s） | `LIBSSL-3-X64 / LIBCRYPTO-3-X64 / LIBFFI-8 / SQLITE3 / ZLIB1 (+ Tk 时 TCL86T/TK86T)` | `runtime_probe.py` P6 实测 |
| `_pth` 隔离语义 | 命中后 `isolated=1`、`no_site=0`（因含 `import site` 行）——与 getpath.py 源码一致 | 实跑 `python.exe -I -c "import sys;print(sys.flags.isolated)"` |
| `import ssl` 可用性 | 在"DLLs 含 pyd + 传递依赖"的布局下通过（OpenSSL 3.5.8） | 实跑通过 |
| Windows `executable_dir` 追加 | ★V15★ `-I` 下仍把可执行文件目录追加到 `sys.path` 末尾 → embedded 时＝安装目录 | 实跑验证，见 `SHELL_PROTOCOL.md` §2.1 |

## 10. 待决策项（M0 D1 落定）
| 项 | 选项 | 决策状态 |
|---|---|---|
| 签名方案 | minisign（850 行 C，体积小、易审计、pinentry） / signify（BSD，~1.5k 行） | ⏳ D1 决策 |
| 标准库形态 | 来源自带 zip / 需 packager 打包成 `<STEM>.zip`，由 D2 实测定案 | ⏳ D2 实测 |
| Android ABI | 单/双 ABI，取决于工控平板 CPU 架构确认 | ⏳ 依赖现场信息 |
| WebView2 离线路径 | A（随包分发 Standalone Installer）/ B（Fixed Version），取决于工控机联网状态 | ⏳ 依赖现场信息 |

---
## 11. 变更记录
| 版本 | 内容 |
|---|---|
| v0.1 | 依据 v8.0 §3/§10 建立；纳入 v8.1 补丁：`min_app_version`（V9）、B.x 派生式修订（V13）、B.s 依赖闭包（V5）、B.t 放置禁令（V4）、B.u pyc 可复现（V12）、B.v certifi（V10）、golden test 负向用例（G5/G6/G7/G8） |
| v0.2 | M0 D2 实测回填：§9 实测已定案表（stdlib 需自行打 zip、`_pth` 需自行生成、依赖闭包清单）、V15 安装目录洁净（G10）、Windows 目标实跑门槛（G11） |
| v0.3 | ★pkapp 0.1.0 实现对账（零机制变更）★：§6 补 spk_hash 精确定义（原空洞条款——manifest 含 spk_hash 而 manifest 在 spk 内，定义为"除 manifest 外全部条目的拼接 sha256"）+ pyc 相对 co_filename 实现注记；B.z 补 ⑥ certifi（v8.2 已定，本文档此前漏抄）；B.v 补"packager 恒装入 certifi"。工具侧落地：Ed25519 签名（M0 D1 决策的 minisign 轻量替代——manifest 正文 Ed25519 签名，壳内置公钥 hex 验签） |
| v0.4 | ★M0 D2 补齐实测回填（PBS cpython-3.12.14+20260929 x64 msvc install_only_stripped）★：① B.t① 探测须用 `python3\d+\.dll` 正则——字典序 python3.dll（稳定 ABI 转发器）排在 python312.dll 前，宽松 glob 选错；② 闭包解析域 = DLLs/ ∪ 根目录（pyd 依赖解释器本体，只扫 DLLs/ 全误报）；③ 系统白名单实测新增：Cabinet/msi（_msi.pyd）、PROPSYS（_wmi.pyd）、IMM32（_tkinter.pyd）；④ python312.dll 动态依赖 VCRUNTIME140.dll（非静态 CRT）→ 根目录伴生 DLL（vcruntime140\*/python3.dll）须随包拷贝（PyInstaller 同款）；⑤ stdlib 排除 test/idlelib/tkinter/turtledemo/site-packages/\_\_pycache\_\_ 后 611 文件 / 12.6MB → python312.zip；DLLs 31×.pyd；runtime.spk ≈ 30.5MB；⑥ G11 实跑通过：解包安装目录形态 + 快照 python.exe 读 python312._pth 启动，sys.path 含 zip 与 site-packages，ssl/sqlite3/asyncio/bz2/lzma 真 pyd 加载成功。证据：pkapp/tools/runtime_probe.py、pkapp/tools/make_runtime_proto.py、pkapp/tests/test_real_runtime.py |
| v0.5 | ★启动优化★：B.u 增补 stdlib zip 预编译 pyc（扁平布局，实测省 ~2s/次启动）——Windows 实测首帧 8.9s → 2.6s（配合 applocal 心跳首拍立即 §6 与 uvicorn 子模块直导） |
