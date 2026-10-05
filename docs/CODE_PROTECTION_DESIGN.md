# pkapp 应用代码保护方案（★v1.4★）

> 状态：**★v1.4 定稿版（2026-10-04，第三轮评审纳入：混淆叠加层二期立项）——②可进入实施**
> 变更记录：★v1.0★ 初稿 → ★v1.1★ 首轮 20 条处置（附录 B） → ★v1.2★ 攻击树诚实化/AAD/加固清单（附录 C） → ★v1.3★ Q1-Q6 决议定稿 → ★v1.4★ **第三轮评审**：核心洞察"杠杆在解密之后"采纳——新增 **§13 字节码/字符串混淆叠加层**（与②正交、二期实施、AST 级 + FastAPI 契约白名单）；壳耦合解锁值**否决**（破坏壳无关/M3）；硬件绑定**否决**（DRM 错位）；补 **§13.7 调试与日志**（混淆不改运行时行为、日志逐字节一致）；见附录 D
> 关联文档：[SHELL_PROTOCOL.md](SHELL_PROTOCOL.md) · [PACKAGER_SPEC.md](PACKAGER_SPEC.md) · [NETWORK_AUTH_DESIGN.md](NETWORK_AUTH_DESIGN.md)
> 讨论背景：用户核心诉求 = **保护自己写的 app/ 业务代码不被阅读**（保密性），非完整性（已有 Ed25519 签名 + spk_hash 覆盖）。

***

## 1. 背景与动机

### 1.1 现状的真正窟窿

- 完整性（防篡改）已有保障：spk manifest Ed25519 签名 + `spk_hash` 文件级校验。
- **保密性为零**：spk 外层 STORED 直存（PACKAGER_SPEC §6），`app/*.py` 以明文躺在包里——解压即读。Android APK 的 assets 同理。
- `pkapp dev` 与构建期均无任何代码形态保护机制。

### 1.2 威胁模型定位

打包产物在用户手里，任何客户端保护都是**抬高逆向门槛**，不是绝对保密。本方案的正确预期：

- ✅ 防解包直读（完整防御）
- ✅ 把"随手可得"变成"需要动态调试技能 + 自研工具"
- ⚠️ 防决心逆向的专业团队：只能加难度，不能杜绝（客户端方案的共同天花板）

**保密边际的诚实表述（★v1.2★）**：K 与密文同包发布——保密边际 = K 混淆段的逆向成本（约一次 IDA 会话），**不是 AES-256**。AES/GCM 在本方案中的真实角色：运行时损坏检测（GCM tag；防篡改本由 Ed25519 负责）+ 结构隐藏的载体（加密清单 + 模块名绑定）。故本方案定性为"**混淆 + 完整性 + 结构隐藏**"，而非密码学保密屏障——评审阅读时勿被"加密"二字带偏预期。

## 2. 目标与非目标

### 目标

- G1 代码保密：spk/APK 中 app/ 代码不可被解包直读；模块名与包结构同样不可见。
- G2 三平台一致：Windows / Android / Linux(M3) 同一套机制，无平台分裂。
- G3 零稳态开销：运行期行为与明文分发逐位一致（解密只发生在 import 瞬间）。
- G4 密码学单源：加密与解密由同一份原生实现承担，Python 侧零加密代码（保 applocal stdlib-only 纪律）。
- G5 可复现：同源码 + 同密钥 → 密文字节稳定 → `app_hash` 构建间不变，指纹缓存机制不受扰。
- G6 零回归：缺省关闭；不开启时构建、dev、打包行为完全不变。
- G7（★v1.1★ 新增）保密不落盘：明文（marshal 载荷）在构建与运行全程不以任何可读形式驻留磁盘；构建期转换仅在 staging 副本上发生，项目源码零触碰。

### 非目标

- N1 防内存 dump：明文字节码终究进 Python 堆，进程内攻击者可钓（所有客户端方案的共同天花板）。
- N2 site-packages 保密：第三方依赖（fastapi/uvicorn 等）保持明文 `.py`（v0.7 裁定不变）。
- N3 防算法泄露的绝对解：真核心算法应服务端化或局部 pyd（见 §9.4）。
- N4（★v1.1★ 新增）结构信息零泄漏：blob 集合仍暴露模块数量与各模块密文体积（文件名为哈希、名字已隐藏，但数量/大小可见）。属可接受泄漏；体积填充（padding）列为可选增强，首版不做。

## 3. 三方案对比与选型结论

| | ① app/ 仅 pyc | ② 加密 + 壳持钥（本方案） | ③ Nuitka pyd |
|---|---|---|---|
| **防护对象** | 解包直接读源码 | 解包 + 拿到文件也读不了 | 需专业原生逆向 |
| **剩余风险** | dis 反汇编可读 | 内存 dump 可得字节码 | 最强，仍非绝对 |
| **平台覆盖** | 全平台 | 全平台（含 Linux，壳无关） | 仅 Windows（Android 无解） |
| **新依赖** | 无 | 无（密码学在原生件内） | Nuitka + C 工具链 |
| **构建变慢** | 无 | 无（毫秒级加密） | +1~数分钟 |
| **体积** | pyc ≈ py | +33 字节/blob（★v1.1★ 核正） | 3-5 倍膨胀 |
| **结构隐藏** | 否（目录可见） | **是**（模块名/结构加密；数量/体积可见，N4） | 部分 |

**选型结论**：

1. ②为推荐主案——跨平台一致、零工具链负担、与①③可叠加。
2. ①作为②的构成步骤（加密 pyc 载荷而非 py），顺带获得"3.12 无成熟反编译器"红利；亦是 Linux 降级兜底（②未实施平台可用①单独防御）。
3. ③作为可选叠加项（Windows 局部核心模块），不在本方案范围内。
4. 关键洞察：项目锁定 CPython 3.12，主流反编译器（uncompyle6/decompyle3 停在 3.8、pycdc 对 3.11+ 残缺）对 3.12 字节码无能为力——仅 pyc 分发在今天就有实际保护力。

## 4. 总体架构：两层分离 + 一个微件

### 4.1 两层分离（解压流程零改动）

```
分发层（不变）：spk → 壳验签 → 指纹比对 → 解压到 _runtime/     ← 壳的一切磁盘契约原样
代码层（新加）：_runtime/app/ 落盘的是密文 blob
              → import 时按需解密（内存）→ marshal.loads → exec
              → 明文全程不落盘（无临时文件、无 __pycache__）
```

明确澄清：**不做"spk 不解压、内存直接加载"**。壳在 Python 启动前读 manifest（文件契约）、ui/ 静态目录、ready/diag/握手码文件、site-packages 目录树全是磁盘路径协议；且②加密后"解压产物落盘"已经无害——"不解压"防的是文件落盘，而本方案防的是**文件内容可读**，为前者推翻壳架构是零收益工程。

### 4.2 密钥生命周期（★v1.1★ 修订）

```
K 生成    首次以 code_encryption=true 构建 → 自动 keygen 生成 .pkapp/code.key（256-bit 随机，与 sign.key
          同级管理，自动入 .gitignore），同时打日志提示备份（丢失 = 无法按原 K 重建，轮换使已发包全量失效）
          （★v1.3★ Q1 决议：自动化；不提供 rotate-key 命令——轮换 = 换 key 文件 → 重新 build + package，均为既有命令）
K 使用-构建  pkapp build：K 明文经 pk_x1(key32,...) 参数传入（内存态，不落盘）→ 加密 app/ pyc 载荷
K 内嵌    pkapp package：K（异或包裹形态）经锚点补丁写入 key-holder 件的 .data 段
K 使用-运行  applocal ctypes 加载 key-holder 件 → pk_x2() → K 只在件内栈上展开
K 轮换    ★v1.1★ 澄清：K 同时是加密钥与 nonce 派生钥——换 K = 重新 build（全量重加密 blobs）+ 重新 package（重打补丁），缺一不可；仅 repackage 会导致旧密文全量 code_decrypt 失败。key_id 随新 K 变化，manifest 与件配对校验（§7.3）
```

K 的存在形态（★v1.1★ 统一口径）：**K 不以明文驻留于任何可读文件；仅以混淆态（异或包裹）内嵌于随包发布的 key-holder 二进制，复原需二进制逆向（见 §5.4②）**。"混淆态内嵌"是本方案密钥防护强度的准确描述——强度 = 那段混淆 + 原生逆向门槛，而非"不在文件里"。

## 5. key-holder 微件设计（核心组件）

### 5.1 定位：一个件、一份实现、两种角色

同一动态库（~400 行 C，单文件，零外部依赖）：

| 阶段 | 形态 | 职责 |
|---|---|---|
| 构建/打包期 | 通用件（K 未内嵌） | `pk_x1()`：构建期加密；package 期接受锚点补丁 |
| 运行期 | 补丁件（K 内嵌） | `pk_x2()`：内存解密；`pk_x3()`：配对校验 |

**为什么密码学必须单源化**：加密解密是同一份 C 代码 → 构建产物与运行期解密永远自洽；Python 侧（pkapp 与 applocal）一行加密代码都不写 → applocal 的 stdlib-only 纪律（_ndk.py 教训：导入链 Discipline）完全不受波及；pycryptodome 依赖及其 Android wheel 可用性风险直接消失。

### 5.2 C 接口（全部导出面 = 三个函数，★v1.1★ 修订）

**★2026-10 防逆向强化：导出名无意义化★**——三个导出更名 `pk_x1/pk_x2/pk_x3`：
导出表与 strings 不再自述"加密逻辑在这"（frida 按语义名挂钩的定位成本抬高；
对照关系仅存于本节与 keylib.py 注释）。函数签名、blob 格式、补丁契约全部不变。

```c
// 构建期：K 由调用方（pkapp）以参数传入——通用形态与"自管形态"通用的唯一加密入口
PKKEY_API int pk_x1(
    const uint8_t *key32,            // 256-bit 项目密钥
    const char    *module_id,        // canonical module id，参与确定性 nonce 派生（§5.4③）
    const uint8_t *in, size_t in_len,
    uint8_t *out, size_t out_cap, size_t *out_len);

// 运行期：无 key 参数——K 从内嵌（混淆）状态栈上展开，用后可移植安全清零（§5.4②）
// module_id 作 GCM AAD（★v1.2★）：blob 只能解成它名下的模块，防包内换位（纵深防御，零成本）
PKKEY_API int pk_x2(
    const char    *module_id,        // 与加密时一致（canonical id）；AAD 不匹配 → code_decrypt diag
    const uint8_t *in, size_t in_len,
    uint8_t *out, size_t out_cap, size_t *out_len);

// 配对校验：key_id = SHA256(K) 前 16 字节 = 32 个 hex 字符（128-bit ★v1.3★ Q6 决议：趁无兼容包袱定死；
// manifest 同存一份）
PKKEY_API const char *pk_x3(void);
```

**★v1.1★ 明确不提供运行时注入 K 的 API（如 `pkapp_set_key`）**：任何注入入口都是攻击者的现成钩子。模式 B（自管件）因此重定义为：**用户自行编译、K 在其构建期内嵌的另一种形态**——`pk_x1` 对两种形态通用（key 走参数），`pk_x2` 恒认内嵌态，接口面不因模式 B 扩大。

### 5.3 blob 格式（★v1.1★ 修订：明文形态精确定义）

```
blob 布局（共 +33 字节/blob）：
offset  0   magic(4)    'PKK1'
offset  4   version(1)  算法/格式版本（未来换算法的退路）
offset  5   nonce(12)   GCM nonce（确定性派生，见 §5.4③）
offset 17   ciphertext  AES-256-GCM(明文载荷, AAD = canonical module id ★v1.2★)
末尾  16   gcm_tag     认证标签（AAD 绑定模块名——防包内换位；spk 签名已防外部篡改，此项为纵深）

明文载荷（★v1.1★ 精确定义）＝ marshal 载荷 = pyc 剥离 16 字节头后的剩余字节
  - pyc 头 16 字节 = magic(4) + flags(4) + [mtime+size 或 source-hash](8)——运行期无意义
  - 构建期剥离、加密；运行期解密后直接 marshal.loads（不再处理头）
  - G5 依赖链：密文稳定 ⇔ marshal 字节稳定 ⇔ 现有子进程编译 + PYTHONHASHSEED=0 机制（assemble 已实证），
    与 pyc 头（含 source hash / mtime）完全解耦——头被剥离，头内不确定性不进密文

nonce 字段定位（★v1.2★ 澄清）：对保密**零贡献**——持 K 与 module_id 者可随手重算；它只是给解密方免重算的便利字段，不是防线（对 G5 的确定性贡献不变）。
```

### 5.4 内部实现要点（★v1.1★ 修订）

1. **算法**：vendor 公有领域 tiny-AES-c（~200 行）+ 精简 GHASH/GCM（~80 行）。选型理由：Linux 不能赌系统有 libcrypto、Android bionic 无 GCM 系统接口、OpenSSL 引入运行时依赖；tiny-AES 吞吐 ~50-100 MB/s，MB 级 app/ 代码解密 <30ms，足够。
2. **K 的静态混淆与可移植清零**：内嵌的不是 K 本体，而是异或包裹态 `stored = K XOR mask`——★隐蔽化（2026-10）★：mask 不以明文常量存于件内，由 `mask = SHA256(seed ‖ 锚点 hex ASCII)` 确定性派生（构建期 Python 侧 hashlib 同式镜像复算；锚点补丁契约不变、二进制锚点唯一性不受扰——ASCII 形态与二进制锚点字节序列不同），32B 常量 XOR 组合的自动特征扫描失效，定位重组点须读懂派生链；`strings` 扫描不可见；★seed 包裹态（2026-10 防逆向强化）★：seed 真值不在件内——件内只存 `SEED_STORED = seed ⊕ SHA256(k_s1 ‖ k_s2)`（k_s1/k_s2/k_seed_stored 三个字节数组空间分散、以字节形态展开，strings 连 hex 串形态也捞不到；seed 真值只存在于构建工具侧 Python 契约常量，不随 dll 分发），运行期 `pk_x2` 调用时 K1 = SHA256(k_s1 ‖ k_s2)、seed = SEED_STORED ⊕ K1 栈上展开、返回前**可移植安全清零**——`SecureZeroMemory` 仅 Windows，统一用 volatile 指针逐字节写零循环（编译器不可省略）或 C11 `memset_s`（可用时优先），杜绝 K 残留栈/寄存器。挡静态扫描，挡不住 IDA 级逆向——预期内（§9）；隐蔽化只抬"一次 IDA 会话"内的会话成本，不改天花板。
3. **确定性 nonce 与 canonical module id（★v1.1★ 精确定义，正确性硬前置）**：

   ```
   canonical module id ＝ 点分 import 名，由 app/ 内相对路径按固定规则派生：
     根包名恒为 "app"（spk 契约目录名）
     app/main.py        → "app.main"
     app/__init__.py    → "app"
     app/sub/x.py       → "app.sub.x"
     app/sub/__init__.py→ "app.sub"
   规则要素（双端一致硬约束）：
     - 只用点分名，不含文件系统路径/分隔符/扩展名——OS 差异与 app/ 前缀歧义从根上消除
     - __init__.py 恒映射到其所在包名
     - 构建期：walk 产出 relpath 后归一化 '/' 再套规则
     - 运行期：finder 收到的 import 名即 canonical id 本身（§7.1），零转换
     - 实施时单测双端对拍（同一批文件名 → 构建端与 finder 端派生结果逐字节一致）
   nonce = HMAC-SHA256(K, module_id ‖ SHA256(payload)[:16])（★2026-10 修订：掺载荷摘要★）
     - 同模块同内容同密钥 → 同密文 → app_hash 跨构建稳定（G5）
     - 不同模块、或同模块不同内容（跨版本重打包）nonce 均不撞——满足 GCM (K, nonce)
       唯一性。★修订原因★：纯 module_id 派生在"同 K + 同模块 + 内容变更"的跨构建
       场景会重用 (K,nonce)（GCM 危险：C1⊕C2 = P1⊕P2，攻击者无需 K 即可对持有
       的两版 spk 差分）；掺 payload 摘要后消除。
     - 解密端从 blob 头读 nonce 不重算——派生公式变更零 blob 格式影响，仅加密端参与
   blob 文件名（★v1.1★ 定义）＝ hex(SHA-256(canonical module id))（完整 64 字符）——
     解耦模块名且跨构建稳定；finder 按 sha256(import 名) 直接定位（§7.1）
   ```
4. **锚点常量**：件内嵌 32 字节锚点（仿壳公钥 `_SHELL_DEFAULT_PUB` 补丁先例），package 期精确命中后原位改写为项目 K 包裹态；未命中即报错（模式 B 自管件不补丁，同壳补丁语义）。
5. **加固取舍（★v1.3★ Q6 决议）**：
   - **进首版**：AAD（核心设计，§5.2/§5.3）；**反调试简单三件套**（Windows `IsDebuggerPresent`/`CheckRemoteDebuggerPresent`；Linux/Android ptrace 自附加——~60 行 C，不做花哨方案）——把最低门槛动态路线（frida hook 导出）抬到需要绕反调试，协同性注记保留：对静态还原 K 路线（§9.1-1B）无作用，与"K 运行时派生"（升级路线）组合才有全值；**key_id 128-bit**（§5.2，一行改动趁无兼容包袱定死）；
   - **★实现落位修订（2026-10-04，AV 误杀对策）★：反调试三件套默认不编入**——AV 启发式对调试 API 引用（导入表项 + 0xCC 断点扫描特征）权重高，是 key-holder 件被误杀的主要自致因素；默认构建（keylib/build.bat 不带宏）不含三件套，需要时在 cl 命令行追加 `/DPKAPP_ANTIDEBUG` 显式重编。`PKKEY_E_DEBUGGER=-5` 语义保留，默认构建不产生该码。本条只改默认值，不改上条"可选加固"定位。
   - **缓行**：key-holder 自校验（.text 校验和——按平台解析段表，真攻击者 patch 后可顺手修校验和，边际低）；运行时明文最小化（mlock/guard page——解密缓冲寿命仅微秒级，code object 残余不可消除，复杂度买不来对应门槛）；
   - **升级路线（不在本期，针对"必须让②本身更难被静态还原"的场景）**：白盒 AES（密钥折叠进查表，"密钥与密文同处一包"的密码学正解；实现/审计成本高，有 BGE 等已知攻击）；K = HMAC(seed, runtime_value) 运行时派生（杀掉离线解密路线，逼攻击者必须运行 + 绕反调试，与反调试项协同）。**明确不做**：远程发钥（服务器首跑下发 K）——破坏离线优先、引入初始信任与单点，为"抬高门槛"付出架构反转，不划算。

### 5.5 三平台落位（全部复用现有机制）

| 平台 | 产物 | 落位 | applocal 取用方式 | 签名覆盖 |
|---|---|---|---|---|
| Windows | `pkapp_key.dll` | exe 旁 | `ctypes.CDLL`（stdlib ✓） | ❌ 无（见 §9.3④） |
| Linux | `pkapp_key.so` | runtime 目录 | 同上 | M3 定 |
| Android | `lib_pkapp_key.so` | jniLibs | `ctypes.CDLL(native_lib_dir/…)`——lib 前缀抽取 + `MYAPP_NATIVE_LIB_DIR` 现成 | ✅ APK 签名覆盖 |

**壳无关性**（对 M3 Linux 的关键意义）：持钥职责已从壳职责中拆出——壳有无、壳如何演进不影响本方案。Linux 无壳照样持钥解密；Android 的 Kotlin 层完全不接触 K（dex 反编译太容易，K 不进任何 JVM/ART 可达内存）。

**Android 落位实现状态（★2026-10 接通★）**：build 期加密与 Windows 同链（`_encrypt_app_tree` 恒用构建机本机 keylib 件，密文与目标平台无关）；package 期 `_stage_keylib(platform="android")` 补丁 `.so` 后经 `build_apk(keylib_so=…)` 拷入壳模板 `app/src/main/jniLibs/<abi>/`。两处平台差异：①key_id 闸门在 Windows 构建机上无法 dlopen ELF 件——改用 Python 镜像 `key_id_hex(K)` 与 manifest 比对（补丁锚点唯一命中保证写入正确性）；②`.so` 必须走 jniLibs（系统按 `nativeLibraryDir` 揭出），app 数据目录 noexec 不能落可执行件。`.so` 构建：`keylib/build_android.bat`（NDK clang，api 24，单 ABI，arm64-v8a 缺省）。

## 6. 构建链改动

### 6.1 assemble.py（build 期，★v1.1★ 修订）

- 新步骤（在现 app/ 拷贝 + pyc 编译之后）：
  1. app/ 树 → 逐模块 pyc（复用 `_compile_checked_hash`，解释器 = 运行时同 minor 快照解释器，版本哨兵既有机制强制——**密文绑定 3.12 pyc magic，错 minor 解释器产出的载荷运行期 marshal 直接失败，此约束从 pyc 时代继承到密文，显式写明**）；
  2. 剥离 16 字节 pyc 头 → `pk_x1(key32, module_id, payload)`；
  3. 落 `app/index.enc`（加密清单：版本、canonical id 列表、Q2 资源条目预留）+ `app/<sha256(module_id)>.enc`；
  4. **顺序硬约束（★v1.1★ 新增）**：单模块流程 = 加密 → 解密回读验证（GCM 打开 + marshal.loads 成功）→ **才**删除 staging 内明文 `.py`/`.pyc`——任何一步失败即中止构建，明文不允许越过"已验证密文"这道闸；
- **转换只发生在 staging 副本**（`tempfile.mkdtemp`，现有管线语义）：项目源码零触碰（G7）；staging 在 finally 清理，进程被硬杀的残留限于 OS 临时目录且随下次构建清场——密文态落盘无害，明文不越闸已在上一步保证；
- **加密清单 `index.enc`**：模块名 → blob 映射关系的加密表——包结构、模块名（"代码地图"）同受保护；finder 以它做成员资格判定（§7.1），避免误吞用户侧同名顶层模块；
- **把 app 目录纳入 `check_closure` 扫描域（★v1.3★ Q5 决议：必做）**——为③ pyd 立项预留健康检查位；
- 非 `.py` 资源文件保持原样明文（★v1.3★ Q2 决议：首版不加密；配套约定——app/ 内不放敏感数据文件，证书/密钥类属配置域应挪出）；
- `tree_hash`/`_emit_spk`/STORED 布局对二进制 blob 无感，`spk_hash`/签名链零改动；

### 6.2 package 期

- 锚点补丁：`_vendor/keylib/<platform>/` 通用件 → staging 副本上改写 K 包裹态（复用壳公钥补丁的锚点命中/回退/多段拒绝逻辑）；
- 补丁后闸门：对补丁件调 `pk_x3` 与 manifest `code_key_id` 比对，失败保留 staging 现场（同现有闸门语义）；
- **模式 B（★v1.1★ 重定义）**：显式自管 key-holder 件（env/参数指定）= **用户自行编译、K 已在其编译期内嵌**的形态——pkapp 不补丁、不需要运行时注入 API（§5.2）；pkapp build 仍用 `pk_x1(key32,…)` 加密（用户向 pkapp 提供 K 与自管件，两者配对由用户自检）。

### 6.3 CI 与 vendor

- `release.yml` 加两个 job：ubuntu（`gcc -O2 -shared -fPIC`）、android（NDK 三 ABI `lib_pkapp_key.so`），产物进 `_vendor/keylib/<platform>/`——vendor.py / package-data 模式照抄现有壳先例（`_vendor/**/*` 显式入 package-data，含 so 后缀）；
- wheel 构建前必须跑 vendor.py（现有约束不变，新增 keylib 目录）。

## 7. 运行时接入（applocal，~100 行，★v1.1★ 修订）

### 7.1 bootstrap 时序与 import 归属（★v1.1★ 解决 PathFinder 冲突）

```
keylib_load    → ctypes 加载 key-holder 件（路径按平台 §5.5）
key_pair_check → 件 pk_x3() 与 manifest code_key_id 比对
finder_install → meta_path finder 插到 PathFinder 之前，独占认领 "app" / "app.*"
import app     → finder：解 index.enc 判成员资格 → sha256(import 名) 定位 blob
              → pk_x2(import 名作 AAD) → marshal.loads → exec
```

- **归属冲突解决（★v1.1★）**：现状 [_core.py#L525-L527](file:///d:/code/pack/applocal/applocal/_core.py#L525-L527) 无条件 `sys.path.append(app_dir)`——加密后 app/ 无 `.py`，PathFinder 会把 app/ 判成 namespace 包。规则改为：**`code_encryption` 生效时 bootstrap 跳过该 append，finder 为 app.* 的唯一供给方（先于 PathFinder 认领）**；不生效时行为与现状逐位一致。两个分支互斥、无竞态。
- meta_path 注册时机安全：bootstrap 本就先于用户代码执行（壳 → PyRun `import applocal` → bootstrap），不存在 _ndk 式"注册来不及"问题。
- **co_filename 归一发生在编译期（★v1.1★ 更正）**：`_compile_checked_hash` 的 `dfile=相对路径`（assemble.py 既有机制，两处编译路径均已是 `dfile=rel`）已把构建机绝对路径挡在 pyc 之外——这同时是 G5（路径不进密文字节）与防构建环境泄漏的保证；运行期**零改动**（code object 不可变，原稿"运行期伪造"说法废除）。
- marshal-exec 路径天然不写 `__pycache__`（仅 SourceFileLoader 会写）——Android 现有 `PYTHONDONTWRITEBYTECODE=1` 不变。

### 7.2 明文生命周期

单模块 import 瞬间存在 → exec 完成 → 解密缓冲即弃。不缓存明文载荷；模块 code object 常驻内存（与现状等价）。

### 7.3 diag 契约（新增 stage，与应用 bug 明确区分）

| stage | 触发 | 用户可见信息 |
|---|---|---|
| `keylib_load` | 件缺失/加载失败 | "代码保护组件缺失——安装包不完整或被裁剪" |
| `key_pair_check` | key_id 不配对 | "spk 与密钥组件不配对——请整体更新应用（勿新旧混装）" |
| `code_decrypt` | GCM 校验失败/文件损坏/marshal 失败 | "代码数据损坏或版本不符——请重装应用" |

**用户可见文案（★v1.3★ Q3 决议）**：三个 stage 的**错误页**统一中性措辞——"应用组件缺失或不完整，请重新安装或更新应用"；上表"用户可见信息"降级为开发者 diag 日志用语，不进错误页（攻击者无法从错误页推断保护策略是否存在）。

### 7.4 与现有机制的边界

- `ROLES` / `ROUTE_PERMS` 读取（`getattr(mod, ...)`）不受影响——exec 后的模块对象与普通模块无异。
- `inspect.getsource` 对 app 代码失效（预期内，与 pyd 同）；RECORD/内省损失为该模式的固有代价，文档注明。

### 7.5 调试影响评估

**开发期（`pkapp dev`）：零影响。** dev 恒跑项目源码，key-holder 不参与、finder 不注册——IDE 断点、uvicorn reload、pytest 照旧。日常调试主循环完全不在本方案作用范围内。

**发行后（打包态）：**

| 能力 | 状态 |
|---|---|
| traceback 的 `文件:行号` | ✅ 行号在字节码中，`co_filename` 编译期已归一为 `.py` 相对路径，错误页/diag/日志照常定位 |
| 异常消息 / docstring / 函数签名 | ✅ 全在 marshal 载荷中（`inspect.signature` 正常，FastAPI 依赖注入不受影响） |
| diag.json / boot-timing.log / selftest 闸门 | ✅ applocal 层机制，与代码形态无关 |
| `dir()` / `help()` / `dis` 交互检查 | ✅ 对 code object 操作，不需要源文件 |
| traceback 源码行片段 | ⚠️ 损失——今天源码随包（v0.7）traceback 可打出出错行；加密后仅 `文件:行号`，对着仓库对应版本看 |
| traceback 变量名（混淆开启时） | ⚠️ ★v1.4★ §13 混淆层使局部/私有变量名混淆——行号保留、定位不受影响，可读性再降一档 |
| `inspect.getsource` 类内省 | ⚠️ 失效——依赖读源码的三方库（调试工具/文档生成器/doctest 类）会出问题；docstring 型 OpenAPI 描述、signature 型依赖注入不受影响（实施 checklist 含 FastAPI 全链路验证点：依赖注入 + OpenAPI 生成） |
| pdb 按行号断点 | ⚠️ 勉强可用（`break 文件:行号` 走 code object，`list` 无源码）——非正常工作流，不承诺 |

**变好的一点**：§7.3 三个 diag stage 把"密钥/组件问题"与"应用代码 bug"显式分开——现状 import 失败只有一句 `No module named 'app'`，加密后反而更可诊断。

**工作流纪律**：现场问题 → 按 release 的 `key_id` + git tag 定位版本 → dev 模式源码复现。开发者持 `.pkapp/code.key`，密文对自己可逆（按 tag 重建即得同构产物）。**发版必须打 tag**——否则 traceback 行号无处对照。

## 8. 配置与开关（★v1.1★ 修订）

- 入口：`[app] code_encryption = true`（缺省 false）。**不碰 `[build]` 硬约束**（残留 [build] 段 = SpecError）。
- 关闭时：无补丁、无密文、finder 不注册、bootstrap 照旧 append app_dir——现有全部行为零变化（G6）。
- `pkapp dev` **显式定义（★v1.1★）**：`code_encryption=true` 时 dev 仍完全忽略该开关——不读 `.enc`、不注册 finder、app/ 仍是源码，防止开发者误以为 dev 也在加密。
- **key 文件管理（★v1.3★ Q1 决议）**：开关开启且 `.pkapp/code.key` 不存在 → 自动 keygen（同 sign.key 先例）+ 备份提示日志 + 自动入 .gitignore；不提供 rotate-key 命令（轮换 = 换 key 文件 → 重新 build + package，均为既有命令）。
- **Linux "未布件" 判定分层（★v1.1★ 修正）**：
  - **构建期判定**只回答"pkapp 能否造出合法加密包"：`_vendor/keylib/linux/` 产物缺失 + 开关开启 → 构建报错（此刻即定局，运行期不可能凭空有件）；
  - **运行期判定**回答"部署态是否完好"：件被裁剪/损坏 → `keylib_load` diag stage（§7.3）+ 错误页；
  - ★v1.3★ Q3 决议：错误页文案统一中性（§7.3）；构建期报错语义保留，不做静默降级。

## 9. 安全分析（★v1.1★ 修订）

### 9.1 攻击者复盘（★v1.2★ 攻击树诚实化：双路线，无先后依赖）

| 步骤 | 动作 | 结果 | 所需技能 |
|---|---|---|---|
| 0 | 解包 spk/APK | 只有哈希名 `.enc` 密文与加密清单，无模块名；结构仅剩数量/体积（N4） | 会解压（到此止步者占绝大多数） |
| 1A | **动态取载荷（低门槛路线）**：运行程序 + frida hook 解密导出（导出名已无意义化 `pk_x2`——按名撞语义失效，须逐个试三个导出或读调用图定位），dump 返回缓冲 | 拿到该次运行实际 import 的模块载荷（可用脚本触发全量 import 补全） | 会 frida——**最低技能档的"全量可得"路线** |
| 1B | **静态离线（一次性路线）**：IDA 逆 key-holder 的 XOR unwrap → 还原 K → 用同一 AES-GCM 实现**离线解密全部 blobs** | **不需要运行进程、不需要 frida**，一次性拿全部载荷 | 会原生逆向（约一次 IDA 会话） |
| 2 | 载荷 → 源码 | 注释永久丢失、docstring 保留；3.12 无成熟公开反编译器 → 只能读 dis/残缺反编译。**若启用 §13 混淆层：产物为改名/去 docstring/常量加密的混淆字节码，可读性地狱级——1B 路线的终局收益大幅打折** | 步骤 1 技能 + 耐心 |

> ★v1.2★ 勘误：v1.1 曾把 frida 列为"静态找 K 之后"的必经步骤——高估了动态路线必要性、错排了顺序。事实：1A 与 1B 是**两条独立路线**，1A 门槛更低，1B 一次性且全量（静态还原 K 后离线解密即完成，动态注入纯属多余）。保密边际由 1B 定义：**一次 IDA 会话**。

**结论矩阵**：会解压/会下工具 → 拿不到任何东西；会 frida → 小时级得（运行中加载的）字节码；会原生逆向 → **一次性离线**得全部字节码，保密边际 = 一次 IDA 会话；专业者重建源码仍有折损（注释丢失 + 反编译器不成熟）。对照③（Nuitka）：③连字节码都不存在，专业者面对机器码，周级且仅近似重建——差距就这一条。

### 9.2 对你有利的现实因素

自研小众方案 vs 知名方案的悖论：PyArmor 功能更强但**有公开脱壳教程和工具**；本方案是定制的，攻击者面对"没有攻略的题"，每步要自己搭。对真实威胁模型（竞争对手顺手扒、用户魔改），这个因素作用显著。

### 9.3 攻击面精确清单（★v1.2★ 定性与分工修正）

1. **保密边际（★v1.2★ 诚实化）**：K 与密文同包发布——静态逆向 key-holder（约一次 IDA 会话）即可**离线全量解密**。保密边际 = 混淆段逆向成本，**不是 AES-256**；本方案 = 混淆 + 完整性 + 结构隐藏（§1.2）。
2. **K 不进**：env（封死进程环境读取）、Python 堆（封死纯 Python heap 扫描找钥）、manifest/spk（封死包内提取）、ART/Dex（封死 Android 高层逆向）；解密在原生层完成——这些路径仍然真实封闭，但都只是"把人往 IDA 路线上赶"。
3. **已知弱点——导出符号可枚举**：★2026-10 强化：导出名无意义化（`pk_x1/x2/x3`）★，strings/语义名直捞失效，frida 须逐个试导出或读调用图——按名挂钩成本抬高；但导出面仍只有三个符号，穷举定位成本仍低——**动态路线（§9.1-1A）是最低门槛路线**。自研方案的优势在"无公开攻略"，不在隐藏导出；序号导出/动态解密 stub 属混淆级可选增强（预期内残留）。
4. **完整性与签名分工（★v1.2★ 澄清）**：防篡改由 `spk_hash` + Ed25519 负责（blobs/清单在 spk 签名域内，替换任一必卡验签）；GCM tag 的价值 = **运行时损坏检测** + AAD 模块绑定（防包内换位的纵深），不承担防篡改首责。Android key-holder 件在 APK 签名域内；**Windows key-holder dll 不具签名**（exe 旁置、补丁后无法哈希钉死）——替换它需安装目录写权限，属"运行时控制"级攻击（与内存 dump 同档，且替换件只能偷跑明文，不能离线解他人拷贝的 spk）。
5. **结构泄漏（N4）**：blob 数量与密文体积可见；体积填充为可选增强。

### 9.4 天花板、有效期与突破路径（★v1.2★ 修订）

明文字节码终究要在 Python 堆 exec——**这是②的地板也是天花板**。分层强制建议（★v1.2★ 从"可选"提级）：**②护全部业务代码（防随手扒），③只护少数真核心算法（防决心逆向），真机密服务端化**——预算优先投给量级跃迁（③/服务端），而非在②上堆白盒/反调试（边际收益低，见 §5.4⑤）。②与③不互斥，可叠加。

**保护有效期风险（★v1.2★ 新增）**：本方案的"字节码→源码折损"严重依赖"3.12 无成熟反编译器"——**这是会随时间贬值的时间窗口**，pycdc/decompyle 追平 3.12+ 后，§9.1 步骤 2 的折损消失，方案剩"混淆 + 结构隐藏"层。正确姿势：把赌注定为"**未来 N 年够用 + 核心走 pyd/服务端兜底**"，并将"反编译工具进展 vs 本方案有效性"列为**周期性重评估项**（升级 CPython minor 不立即失效，工具成熟才失效）。

## 10. 决策记录（★v1.3★ 定稿，Q1-Q6 双方确认）

| # | 决议 | 落点 |
|---|---|---|
| **Q1** key 文件管理 | **自动 keygen**（首次加密构建自动生成 + 备份提示日志 + 自动入 .gitignore）；**不配 rotate-key 命令**（轮换 = 换 key 文件 → 重新 build + package，均为既有命令） | §4.2 / §8 |
| **Q2** 非 .py 资源 | **首版不加密**；配套约定：app/ 内不放敏感数据文件（证书/密钥类属配置域，应挪出） | §6.1 |
| **Q3** 错误页文案 | **三 stage 统一中性文案**（"应用组件缺失或不完整，请重新安装或更新应用"），不暴露保护策略；构建期报错语义保留，不做静默降级 | §7.3 / §8 |
| **Q4** 开关粒度 | **单开关 `code_encryption`**（①隐含其中，不单独暴露——两态分支测试面最小） | §8 |
| **Q5** pyd 组合 | **单独立项，不绑进本方案**；衔接动作：`check_closure` 扫描域扩展升级为**必做**（为③预留健康检查位） | §6.1 / §9.4 |
| **Q6** 首版加固取舍 | **进首版**：AAD（核心）+ 反调试三件套（~60 行 C）+ key_id 128-bit；**缓行**：自校验、明文最小化；**升级路线**：白盒 AES / K 运行时派生；**不做**：远程发钥 | §5.2 / §5.4⑤ |

> 决策依据（2026-10-04 讨论）：若威胁为"随手扒/用户魔改"，本方案已超额满足，加固堆叠边际收益低；高价值算法的预算投向③/服务端（§9.4 分层强制建议）。

**★v1.4★ 第三轮评审新增提案决议**：

| # | 提案 | 决议 | 理由 |
|---|---|---|---|
| Q7 | **字节码/字符串混淆叠加层** | ✅ **采纳，二期立项** | 补"解密之后"最弱漏点，与②正交，全约束自洽——独立成 §13 |
| Q8 | **壳耦合解锁值**（壳持钥二次包裹 key-holder） | ❌ **否决进首版**，记录为可选方向 | 破坏壳无关架构（M3 Linux 失效需回退①）；收益 = "一次 IDA 变两次"，与 Q6"加固堆叠边际收益低"同构。若未来 M3 端确认小体量/非敏感，可重评 |
| Q9 | **硬件绑定密钥**（Keystore/DPAPI/TPM） | ❌ **不做** | 防"拷包别处跑"（DRM 味），不防原机 frida——与核心诉求（防读代码）错位；评审自查结论一致 |
| Q10 | 白盒 AES / Nuitka 全量 | 维持既有决议 | 白盒留升级路线（§5.4⑤）；Nuitka 全量已否（Android 无解），仅③局部核心 |

## 11. 工作量拆分（估算）

| 项 | 规模 |
|---|---|
| key.c（tiny-AES + GCM/AAD + K 混淆 + 可移植清零 + 反调试三件套 + 三导出） | ~460 行 C + 单测（GCM 已知向量验证 + 清零汇编审查） |
| CI 双平台产物 + vendor.py 扩展 + package-data | 半天级 |
| assemble.py 加密步骤（strip 头/确定性 nonce/清单/加解密回验/删明文闸/check_closure 扫描域/keygen） | ~140 行 |
| applocal finder（成员判定/归属互斥/diag 契约/bootstrap 分支） | ~150 行 |
| package 锚点补丁复用改造（含补丁后闸门） | ~50 行 |
| 测试（配对/缺件/损坏/跨 key 拒绝/dev 旁路/关闭零回归/G5 密文稳定/双端 module id 对拍/FastAPI 注入与 OpenAPI 链路验证） | 与实现同量级 |
| **【二期 §13】混淆 pass（AST 改名/docstring 剥离白名单/选择性字符串加密 + stub 注入）** | ~400-600 行 Python + FastAPI 契约硬闸门测试 |

整体落在 300-500 行 Python + ~400 行 C 框内。建议实施顺序：**key.c + Windows 单平台全链先通 → Android 落位（jniLibs 机制）→ Linux 随 M3**。

## 12. 性能预算（★v1.1★ 修订，拆开两件事）

| 阶段 | 开销 | 量级 |
|---|---|---|
| 构建期 | AES 加密 app/ 代码 | KB~MB 级，毫秒级，构建无感 |
| 启动期·本方案增量 | 每 import 一次 GCM 解密 + marshal.loads（惰性，只解被引模块） | 单模块 µs~0.1ms；helloApp（2 模块）合计 <1ms |
| 启动期·既有基线（对照，非本方案开销） | pyc 编译/import 链 | 8.9s→2.1s 优化历史中的既有项，与加密无关 |
| 运行期 | **零** | code object 与明文分发逐位一致，无包装层/拦截 |
| 体积 | **+33 字节/blob**（magic4+ver1+nonce12+tag16）+ 密文≈明文 | 对比 pyd 3-5 倍膨胀 |

验证工具现成：`boot-timing.log` 的 `_tmark` 打点链，实现时在 finder 解密处补一个打点即可量化。

## 13. 字节码/字符串混淆叠加层（★v1.4★ 新增，二期实施；★已实现★——构建开关 [app] code_obfuscation，缺省关闭）

### 13.1 定位：补"解密之后"的最弱漏点

第三轮评审的核心洞察：②的攻击链里，K 还原（§9.1-1B）是一次性固定成本，真正的价值泄漏在**步骤 2——解密产物是干净源码级字节码**。混淆层与②**完全正交**：构建期对 app/ 源码做 AST 级变换后再编译/加密，即使对手走完 1B，拿到的也是改名/去 docstring/常量加密的字节码。对目标威胁档位（竞品随手扒/用户魔改），这是量级跃迁且与②复利相加。

**约束自洽**：纯构建期 Python 变换——零原生工具链、三端一致、离线、不碰 applocal 的 stdlib-only 纪律、AST 变换确定性（G5）。可脱离②独立启用（Linux ①兜底路径同样受益）。

### 13.2 管线位置与配置

```
assemble：app/ 源码 → [混淆 pass（若开启）] → AST → compile → pyc → [strip 头 → 加密（若开启）]
配置：[app] code_obfuscation = true（缺省 false；与 code_encryption 正交，四象限组合均合法）
.enc 格式不变（仍是 marshal 载荷）——混淆开关不影响 ② 的产物契约，二期加入零迁移成本
```

### 13.3 变换范围（v1）

1. **局部名/私有符号改名**（AST 级作用域安全变换，非原始字节码改写——3.12 字节码格式变动大，AST→compile 是唯一稳路）；
2. **docstring 剥离**（白名单豁免，见 13.4——FastAPI 拿路由函数 docstring 作 OpenAPI description，盲剥会打崩文档）；
3. **选择性字符串/常量加密**（长字面量；构建期加密、注入 stdlib-only 惰性解密 stub 进模块字节码，运行时首次使用时解）——业务"精华"多在字符串（prompt/SQL/规则文案/接口约定），此 pass 比改名更能藏住真东西。诚实注记：字符串解出后进 co_consts 常驻内存，N1 残余不可消除；惰性解把"离线读字符串"逼成"必须运行 + hook stub"，动态成本上升。

### 13.4 白名单（FastAPI 契约保护，硬约束）

盲目改名直接打崩接口契约。以下符号**保留原名**：

- 路由处理函数名（OpenAPI operationId 派生源）+ 其 docstring；
- pydantic model 字段名（请求/响应字段映射）；
- 被 `Depends`/`Annotated` 引用的符号；
- `__all__` 导出符号、模块级公共 API；
- doctest 所在 docstring（若项目使用）。

设计原则：真正想藏的核心算法多半在私有函数/局部作用域里——白名单与保护目标天然不冲突。

### 13.5 风险与测试闸门

- **FastAPI 契约测试为硬闸门**：请求字段映射、端点识别、OpenAPI 生成全链路比对（混淆开/关各跑一遍，响应 JSON 逐字节一致）；
- traceback 可读性进一步下降（行号保留、变量名混淆）——§7.5 已注记；
- 改名映射表不落盘（编译期一次性），无额外泄密面。

### 13.6 实施排序与工作量

**二期**——②首版全链（key.c → Windows → Android → 回归）打通后立即立项。理由：②已定稿且独立可发；混淆层设计风险最高（FastAPI 契约）需要自己的测试周期。工程量 ~400-600 行 Python + 契约测试，构建期开销毫秒级。

**实现落位（★已实现★，2026-10-05）**：13.3①②③ 全部落地，统一开关 `[app] code_obfuscation`。实现形态与设计的对应：
- 新模块 `pkapp/pkapp/packager/obfuscate.py`（纯 stdlib ast/symtable/hashlib）：symtable 驱动作用域安全改名（函数 scope 局部绑定 → `_o{n}` 首现序；参数/类体内名/global/import 绑定/dunder/模块级名**全部不改**——合同面从严）+ docstring 剥离（带装饰器函数/class/含 doctest 豁免）+ 选择性字符串加密（`len>=16` 纯 str 值位替换；装饰器参数/默认参数/注解/match case/`__all__`/f-string 从严豁免）+ stdlib-only 惰性解密 stub（`_pkobf_d`/`_TBL`，解出回写一次性缓存）；
- 行号保留：`compile(ast_obj)` 原lineno（不落 ast.unparse 的重排行号坑）；checked-hash pyc 组装 `_code_to_hash_pyc(code, source_hash(原始源字节))` 与 py_compile 逐字节相等（实测），磁盘 .py 不改写 → importlib 校验自洽、traceback 行号即源码行（13.7 契约兑现）；
- 确定性（G5）：改名按首现序、keystream = SHA256(obf_key‖module_id‖counter)（`.pkapp/obf.key` 与 code.key 同级管理，幂等 keygen；混淆层不依赖 K，四象限正交）；stub 内 key32 以 XOR 包裹态双常量分持，不明文内嵌；
- 编译链：快照解释器子进程 obf 分支（`_compile_checked_hash(obfuscate=True, obf_key=...)`），embed 环境 sys.path 注入 packager 目录后 import obfuscate；进程内回退同款；PYC-OK 行带 renamed/stripped/strings 统计；
- 变换不落盘映射表；`pkapp dev` 跑源码零参与（13.7 表）。

**叠加后的对手完整成本**：逆 XOR 拿 K → 离线解密 → 再啃混淆字节码 + 需运行才能解出的字符串。对目标威胁档位为"劝退级"，工程成本远低于白盒/反调试堆叠（§5.4⑤ 取舍逻辑不变）。

### 13.7 调试与日志（★v1.4★ 补）

**核心不变量：混淆改的是"代码的形态"，不是"运行时的行为"。** 日志输出**逐字节一致**——字符串字面量构建期加密、运行时首次使用即解密还原，`logger.info`/异常消息/格式化输出全部原样。混淆 pass 的语义不变式就是"跑起来一模一样，只是源码形态变脏"。

分调试场景：

| 场景 | 影响 |
|---|---|
| 日常开发调试（`pkapp dev`） | **零影响**——dev 跑源码，混淆层不参与 |
| 发行版问题第一响应 | traceback `文件:行号` **保留**（AST 变换不动行号）+ "发版打 tag"纪律 → 行号直接对应仓库源码行 |
| 仅发行版可复现的 bug | 日志（不受影响）+ diag 三件套（boot-timing/selftest/diag stages，读运行时状态不读源码）全部保留 |

调试信息各要素状态：日志内容/异常消息/traceback 行号/公共与路由函数名（白名单）——✅ 保留；私有与局部符号名（`_validate_token` → `_a3f2`）、docstring（白名单豁免路由函数，OpenAPI 不受影响）、源码行片段（已随②损失）——⚠️ 损失或混淆。

**设计取舍重申**：唯一实质下降是私有符号的 traceback 可读性——公共 API 全保留、被混淆的恰是内部实现，与"藏核心算法"的目标天然一致。顺带的保密增益：日志文案也被常量加密覆盖，攻击者拿 `.enc` 连日志文案都 grep 不到——调试信息对发行者透明、对扒包者不透明。

---

## 附录 A：与既有决策/约束的对照清单（★v1.1★ 增补两行）

| 硬约束/先例 | 本方案兼容性 |
|---|---|
| pkapp.toml 无 [build] 段（SpecError） | ✅ 开关放 [app] |
| applocal stdlib-only 纪律 | ✅ ctypes 是 stdlib；密码学全在原生件 |
| site-packages 恒只带 .py（v0.7） | ✅ 不触碰 |
| app/ 恒保留源码（v0.7 默认） | ⚠️ 开启本方案即偏离——属 opt-in 模式，默认路径不变 |
| 锚点补丁先例（_SHELL_DEFAULT_PUB） | ✅ 机制复用，K 为新锚点 |
| Android jniLibs lib 前缀机制 | ✅ key-holder so 直接复用 |
| G1 字节级可复现 | ✅ 确定性 nonce + 哈希 blob 名 + 编译期 dfile 归一 |
| wheel 构建前必须跑 vendor.py | ✅ keylib 纳入既有流程 |
| 单 ABI 构建（android） | ✅ key-holder so 按 ABI 落 jniLibs，与现约束同构 |
| **pyc 解释器版本哨兵（assemble 既有）**（★v1.1★） | ✅ 密文载荷继承同一约束：构建必须用与运行时同 minor 解释器 |
| **staging 临时目录语义（assemble 既有）**（★v1.1★） | ✅ 明文转换只在 staging 副本，项目源码零触碰 |

## 附录 B：线下评审意见处置记录（20 条，★v1.1★）

| # | 评审要点 | 核实结论 | 处置 |
|---|---|---|---|
| 1 | K"落盘"自相矛盾 | ✅ 成立 | §4.2/§9.3 统一口径："不以明文驻留可读文件；混淆态内嵌随包二进制" |
| 2 | 模式 B 无注入入口 | ✅ 成立（设计缺口） | §5.2/§6.2 模式 B 重定义为编译期内嵌形态；明确不提供注入 API（入口即攻击面） |
| 3 | 轮换需重加密不止 repackage | ✅ 成立 | §4.2 轮换 = 重新 build（重加密）+ 重新 package（重补丁） |
| 4 | module_path 需 canonical 定义 | ✅ 成立（正确性硬前置） | §5.4③ 定义 canonical module id = 点分 import 名（无路径/分隔符/扩展名歧义），双端单测对拍列为实施项 |
| 5 | 明文 = pyc 整文件还是 code object | ✅ 成立（marshal.loads 不吃 pyc 头） | §5.3 定义为"剥离 16 字节头后的 marshal 载荷"；G5 与 pyc 头不确定性解耦 |
| 6 | bootstrap append 与 finder 抢归属 | ✅ 成立（评审引注行号 313 有误，实为 _core.py:525-527，机制指认正确） | §7.1 加密态跳过 append + finder 先于 PathFinder 独占认领，两分支互斥 |
| 7 | SecureZeroMemory 仅 Windows | ✅ 成立 | §5.4② 改可移植清零（volatile 循环 / memset_s） |
| 8 | blob 文件名 hash 未定义 | ✅ 成立 | §5.4③ 定义 = hex(SHA-256(canonical id)) 全长 64 字符 |
| 9 | overhead 28 vs 33 | ✅ 成立（28 为算错） | §5.3/§12 统一为 +33 字节/blob |
| 10 | Linux 未布件判定层错位 | ⚠️ 部分成立（构建期"vendor 无产物"判定仍必要——件随包发布，构建即定局） | §8 分层：构建期卡产物存在性，运行期 diag 卡部署完好性；Q3 重述 |
| 11 | pyc 与 CPython 版本绑定未写明 | ✅ 成立（代码层已有版本哨兵，文档缺约束声明） | §6.1/附录 A 显式写明同 minor 解释器约束 |
| 12 | co_filename 应编译期而非运行期 | ✅ 成立（dfile=rel 既有，原稿运行期伪造说法错误；另指出绝对路径进 pyc 会破坏 G5——正确） | §7.1 更正为编译期归一，运行期零改动 |
| 13 | 结构泄漏应明示 | ✅ 成立 | §9.3⑤/N4 明示（数量/体积可见），padding 列可选增强 |
| 14 | key_id 位数应写明 | ✅ 成立 | §5.2 注明 16 hex = 64-bit，碰撞 ~2^-32 量级 |
| 15 | 删明文需失败保护 | ✅ 成立（补充：转换本就在 staging 副本，项目源码零风险；残余风险在 staging 内部顺序） | §6.1 加密→回验→才删明的顺序闸 + staging 语义说明 |
| 16 | getsource 踩坑类型 + FastAPI 验证点 | ✅ 成立 | §7.5 补三方库类型清单 + FastAPI 注入/OpenAPI 链路列入实施 checklist |
| 17 | dev 行为需显式 | ✅ 成立 | §8 显式定义 dev 完全忽略开关 |
| 18 | 补"篡改必卡验签" | ✅ 成立（需细分：Windows key-holder dll 无签名，属运行时控制级攻击） | §9.3④ 按签名覆盖域分层说明 |
| 19 | §12 基线混述 | ✅ 成立 | §12 拆分"本方案增量"与"既有基线"两行 |
| 20 | 导出名固定 = hook 点好找 | ✅ 成立（诚实弱点） | §9.3③ 明示；导出名随机化列为可选混淆增强 |

评审行号勘误：#6 所引 `_core.py:313` 实为 `_core.py:525-527`（bootstrap 的 `sys.path.append(app_dir)`），机制指认不受影响。

## 附录 C：第二轮评审意见处置记录（★v1.2★）

| 评审要点 | 核实结论 | 处置 |
|---|---|---|
| **定性**：K 与密文同包 → 保密边际 = XOR 混淆强度（一次 IDA 会话），非 AES-256；AES 真实角色 = 运行时损坏检测 + 结构隐藏载体；建议改口"混淆+完整性+结构隐藏" | ✅ 完全成立——v1.1 §9.3 措辞仍让人误以为有密码学保密屏障 | §1.2 新增"保密边际诚实表述"；§9.3① 定性改写；文档标题本就中性（"保护"）未动 |
| **攻击树勘误**：静态还原 K 后即可离线解密全部 blobs，"需 frida"高估了动态路线必要性 | ✅ 成立——v1.1 把 1B（静态离线）与 1A（动态）错排成先后依赖，且漏掉"还原 K 后无需运行"的终局 | §9.1 重构为 1A（低门槛动态）/1B（一次性静态离线）**双独立路线** + 勘误注记；结论矩阵同步改写 |
| 保留项确认：结构/模块名隐藏是实增益；3.12 反编译窗口是最硬天然屏障；确定性 nonce/key_id 64-bit 正确 | ✅ 确认 | 无需改动（§5.4③/§5.2 已如此表述） |
| nonce 字段对保密零贡献 | ✅ 成立 | §5.3 明示"便利字段，非防线" |
| 廉价加固：反调试 / 自校验 / 明文最小化 / AAD / key_id 128-bit | ✅ 全部成立，其中 AAD 零成本纯增益 | **AAD 进核心设计**（§5.2 decrypt 加 module_id 参数 + §5.3 blob 定义 + §7.1 finder 传参）；其余进 §5.4⑤ 可选清单 + §10-Q6 取舍；**补注记：反调试单独价值有限，需与 K 运行时派生协同**（静态路线绕开它） |
| 中等投入：白盒 AES / K 运行时派生 | ✅ 成立（白盒是"密钥密文同包"的密码学正解，成本/已知攻击评价准确） | §5.4⑤ 列为升级路线，不在本期 |
| 远程发钥 | ✅ 同意不做（破坏离线优先 + 初始信任 + 单点） | §5.4⑤ 明确"不做"及理由 |
| pyd 分层从"可选"提为"核心算法强制项" | ✅ 成立 | §9.4 提级为分层强制建议；§10-Q5 同步 |
| 时间风险：3.12 反编译窗口会贬值，需周期性重评估 | ✅ 成立且重要 | §9.4 新增"保护有效期风险"段；赌注表述改为"未来 N 年够用 + pyd/服务端兜底" |
| 排序建议（威胁随手扒→v1.1 已够+攻击树诚实化+反调试；高价值算法→③/服务端；白盒仅特定场景） | ✅ 采纳为决策框架 | §10-Q6 + §9.4 落实 |

一处措辞保留意见：评审"任何拿到安装包的人都能还原 K"中的"任何人"偏强——1B 路线仍需 IDA 级原生逆向技能（这正是边际所在），但方向判断完全正确，已按其精神修订。

## 附录 D：第三轮评审意见处置记录（★v1.4★）

| 评审要点 | 核实结论 | 处置 |
|---|---|---|
| **核心判断**：约束（密钥同包/离线优先）下"加密"必然退化为"混淆"，杠杆在"解密之后"——1B 走完后业务代码在 dis 下完全可读 | ✅ 成立且是三轮评审中最有价值的洞察——v1.3 前方案对步骤 2 零防护 | 新增 **§13 混淆叠加层**（二期）；§9.1 步骤 2 更新；§7.5 增变量名注记 |
| **① 字节码+字符串混淆层**（强烈建议加入） | ✅ 采纳。补两处评审未点透的坑：docstring 剥离会杀 FastAPI OpenAPI 端点描述（白名单须豁免路由函数 docstring）；变换须走 AST 级而非原始字节码（3.12 格式变动大）+ 确定性（G5） | §13 全节；配置 `[app] code_obfuscation` 与 `code_encryption` 正交（四象限合法，Linux ①兜底路径同样受益）；`.enc` 格式不变 → 二期零迁移成本 |
| 字符串字面量在 marshal 载荷明文可见 | ✅ 属实（co_consts 不加密），prompt/SQL/规则文案确实裸奔 | §13.3③ 选择性字符串加密列为 v1 变换之一；诚实注记 co_consts 常驻内存残余（N1） |
| **② 壳耦合解锁值** | ⚠️ 技术成立但架构代价明确——评审自查"放弃壳无关 → M3 失效" | **否决进首版**（Q8）：收益"一次 IDA 变两次"与 Q6 边际判断同构；记录为可选方向，M3 端定位明确后可重评 |
| **③ 硬件绑定密钥** | ✅ 评审自查正确：DRM 味、不防原机 frida、与"防读代码"错位 | **不做**（Q9），防遗漏记录在案 |
| 白盒 AES / Nuitka 全量不推荐 | ✅ 与既有决议一致 | 维持（Q10）：白盒留升级路线，Nuitka 仅③局部核心 |
| 推荐组合 ②+①（+③天花板） | ✅ 采纳为路线图 | 首版 ②（§4-§8，已定稿）→ 二期 §13 混淆层 → 天花板 Q5（③ pyd 单独立项/服务端） |
