# 引导面完整性校验方案（P0）——评审稿

状态：评审完成（R1 10 项 + R2 5 项已折入；Q1-Q8 已拍板，见 §10）——可开工
日期：2026-10-07
关联文档：PROTECTION_ROADMAP（本方案拟作为新增章节）、CODE_PROTECTION_DESIGN §7/§8、SHELL_PROTOCOL §5、PACKAGER_SPEC §2

---

## 0. 一句话

壳（native）在把控制权交给 Python 之前，对引导面**全部落盘文件**执行「清单严格相等 + 逐件哈希」校验；任何注入或篡改在第一条应用代码 import 之前 fail-closed。

```
壳 exe（native 信任根）
  → 每启重验清单签名（★R1-4★ 公钥埋壳内，签名侧车见 §4.2——两道校验都每启现算）
  → 递归枚举引导面、逐件现算 SHA-256，与清单做对称差比对
      ├─ 全部一致 → PyRun_SimpleString("import applocal…")
      └─ 任何失配/多余/缺失 → 现成中性错误页 fail-closed
```

---

## 1. 背景与实锤（为什么现在做）

### 1.1 逆向演练暴露的信任根断链

对发布包 `helloApp-0.1.0-windows-x86_64` 的完整离线逆向（全程未 attach 进程）成功还原全部 8 个应用模块。复盘发现的最短攻击路径不是离线链，而是**盘上注入**：

- 交付包内 `_runtime/site-packages/applocal/` 为**明文可写** `.py`（`_core.py` 30KB、`_gate.py` 17.7KB、`session.py`、`rbac/`），而 `applocal.bootstrap()` 正是壳引导的必经之路（shell.cpp：keylib 解 `_codekey` blob exec 注入后，`PyRun_SimpleString("import applocal; applocal.bootstrap(entry)")`）；
- **spk 验签只覆盖首启解包**，解包缓存命中后不再复验——篡改随缓存永久生效；
- `python312._pth` 含 `import site` → site-packages 的 **`.pth` 自动执行是活的**（在 applocal 加载之前即可执行任意代码）；`._pth` 本身可写（可前插路径 shadow 整个 applocal）。

### 1.2 三个攻击面（按危害排序）

| # | 攻击面 | 性质 |
|---|--------|------|
| 1 | 鉴权绕过：改一行 `_gate.py` = 免密 admin；植入恶意代码 = 应用沦为投毒载体 | **安全漏洞**，与逆向收益无关 |
| 2 | RE 捷径：注入数行 hook `load_code` → 一次启动 dump 全部解密 marshal（EncFinder/pycdc/_strmaps 等离线工具链全部不需要） | 保护击穿 |
| 3 | 同层旁路：`.pth` 自动执行 / `._pth` 篡改 / pyc 伪造头加载 | 保护击穿 |

### 1.3 与既有防线的关系（立项依据）

信任根断链期间，任何其他防护投入（RFT 改名 / mix-str 字符串加密 / K 派生体系 / BCC）都可被一次文件写入绕过——沙上建塔。本方案是后续所有防线投资的前提。

---

## 2. 威胁模型（防什么 / 不防什么）

| | 内容 |
|---|---|
| ✅ 防 | 盘上注入全家：改 `_core.py` 等源码 / 伪造 pyc / 丢 `.pth`、sitecustomize / 改 `._pth` / 松散文件影子 / patch `.so` / 改 deps.zip 内容 |
| ✅ 效果 | 攻击者被推回**纯离线链**（解密→反编译），离线链成本由既有防线（K 体系/RFT/mix-str）与后继 P1/P2 承担 |
| ❌ 不防 | 壳 exe 自身被 patch（校验逻辑被 NOP）——§6 既有残余口径，缓解靠壳签名/自检；运行期内存 dump（1A）；服务器 root / 物理访问（§1 边界外） |

**边界声明（免得误判难度）**：本方案解决完整性 / 启动性能 / 清单可维护性，**不解决混淆**。deps.zip 里的 pyc 对 pycdc 只是多一步 unzip，离线反编译成本不变。抬离线成本是 P1（mix-str 绑 K）与 P2（BCC / 种子扩容）的职责，两条线分开记账。

---

## 3. 方案总览

| 阶段 | 内容 | 定位 |
|------|------|------|
| **P0** | native 完整性校验 + deps.zip 落盘形态重构（本文档主体） | 安全修复 + **使能器**：没它，P1/P2 都能被"改文件"绕过（patch `_core.py` 短路 K 派生即可，无需任何逆向） |
| **P2** | 种子扩容：`_codekey` 模式已存在（壳解密→exec 注入，15KB .enc 先例），把 `_core/_gate/session/_env` 并入加密 blob 通道，site-packages 不再分发明文 applocal | **结构修法，性价比最高**：从源头消除明文注入面 + applocal 无明文可读；P0 后第二优先 |
| **P1** | mix-str 密钥绑 K_app：stub 自裹密钥（`_k = A^B` 离线可解）→ `HKDF(K_app, module_id)`，字节码只留运行期取钥调用；G5 默认档安全 | **离线链减速带（非主防线）**：字符串解密与 K 提取成本相乘；P0 后价值才成立 |
| 远期 | BCC（Cython）/ 档位3 白盒 / 档位4 硬件证明 | roadmap 既有口径不变 |

> **依赖与定位红线（拍板补充）**：P1/P2 的价值都以 P0 为前提——盘上代码可改时，攻击者直接 patch 引导代码让 K 派生短路、返回明文，混淆再强也无需被"逆向"；P0 封死改文件路径后，P1/P2 才对**纯离线逆向者**生效。三件套 collectively 只覆盖两类攻击者：**盘上有限写**（P0 检测 + P2 消除明文面，双保险）与**纯离线分析**（P1/P2 抬成本）。对"游戏结束"级威胁——服务端 root/机器 admin（换壳+换公钥）、运行期内存 dump、壳 exe 被 patch——三道全部无效，由 **§9 平台签名 + 部署权限分离**承担。两条定位红线：**P1** 仅是离线 RE 减速带，不得作为"保护密钥/代码"的主防线对外宣称（防虚假安全感）；**P1 可在 P2 实施窗口内穿插落地**（体量小、不依赖 P2），穿插不构成对 P2 优先级的否定。

> **原 P0.5（applocal pyc-only）并入 P0，不再单列**：终态即 P0 落盘形态的一部分（§4.1）；脱离清单体系的裸 pyc 无独立保护力（伪 8 字节头即破，见 §4.6）；实现上由 staging compileall 统一产出（§7），P2 之后 applocal 进 blob，盘上形态还会再变，过渡形态最少化。

---

## 4. P0 设计：deps.zip 形态 + native 完整性校验

### 4.1 落盘形态（终态）

```
构建期：pip install（staging）
  → compileall --invalidation-mode=unchecked-hash（pyc 头与构建时间解耦）
  → 纯 Python 发行版收拢 deps.zip（内 pyc-only，剥 .py，zip 条目时间戳钉死）
  → 含原生扩展的发行版整目录散件化（pydantic_core 的 .pyd 与其 pyc 同目录）
  → packager 生成 python312._pth（path 收窄）

_runtime/
  ├─ python312._pth            ← packager 生成，进清单
  ├─ python312.zip / DLLs 等    ← runtime 根件，进清单
  └─ site-packages/
       ├─ deps.zip             ← 第三方树整体（1 条哈希）
       ├─ applocal/            ← pyc-only 散件（原 P0.5，并入 P0）
       └─ pydantic_core/ 等    ← 含 .so/.pyd 的发行版散件目录
```

`._pth` 条目规则：纯 Python 发行版 → `site-packages/deps.zip` 一条；含原生扩展的发行版 → 散件目录一条；**`site-packages/` 本身不上 sys.path**。

**unpack 语义变化**：spk 直接携带固化环境（deps.zip + 散件目录 + 清单），解包退化为「拷文件 + 落盘」，不再 pip install——首启更快（省 pip 解析安装），环境跨机器确定（与 G5 指纹钉版本同一条哲学线）。

### 4.2 清单规范

- **覆盖面 = 受保护树递归全覆盖**（★R1-6★）：受保护区 = `site-packages/` **整棵树** + runtime 根**整棵树**（含 `._pth`/zip）——递归枚举到叶子，不是 top-level；「会执行的文件都要在清单里」，含 `.so/.pyd` 与根层可执行件；
- **规则 = 集合严格相等 + 逐件 SHA-256**：清单内文件必须存在且哈希一致；受保护树内**任何清单外文件**（多出来的 `.pth`/`sitecustomize`/松散 `fastapi.py`/伪造 pyc）一律 fail-closed——不逐类型枚举注入点，用集合相等一网打尽；
- **实现语义 = 递归枚举 + 对称差**（★R1-2★，防实现走样的关键）：walk 整个受保护目录树 → 算出实际 `{相对路径: hash}` 集合 → 与清单做**对称差**，非空即 fail。**禁止**实现成"遍历清单逐条 stat+hash"——那会让清单外文件永不被查，影子文件洞在实现层复活（§7 已补此条）；
- **清单为签名侧车，每启重验**（★R1-4★）：构建期对清单字节单独签名（公钥埋壳内），清单以侧车形态随包落盘；每启顺序 = 先验清单签名（几 KB，毫秒级）→ 再做文件哈希对称差。两道都现算、都不信任解包缓存——堵住"验签后、缓存期内换清单+文件"的旁路。备选（每启全量 spk 验签）见 Q7。**侧车为信任锚，位于受保护树枚举范围之外**（★R2-4★，推荐落位：与壳同级 `integrity.manifest` + `integrity.manifest.sig`）——不参与对称差，缺失或验签失败直接 fail-closed；否则实现者若把它丢进受保护树枚举，会出现"用清单哈希校验清单自己"的自引用死结。★Q7★ 密钥复用现有 spk 验签密钥对（不引入第二把密钥）；壳读取合同：`write_bytecode=0` 后、`PyRun` 前以 exe 所在目录为基准读同级侧车。

### 4.3 校验流程

1. **时机**：native 侧、`PyRun_SimpleString` 之前（一旦 import 发生，恶意代码已执行，之后做什么都晚）；
2. **频率**：每次启动现算，**不信任解包缓存**（现状之洞正是"验签只管首启"）；
3. **不做结果缓存**：任何"上次验过"标记都会把信任基础改回磁盘历史，洞从缓存重新进来；
4. **运行期零写入**：壳初始化 `PyConfig` 时置 `write_bytecode = 0`——`__pycache__` 从源头不再出现，"集合严格相等"在每次启动时都成立；
5. **升级清残（显式时序）**（★R1-3★，★R2-3★）：每启顺序固定为 ①**验清单签名**（缺侧车/验签失败 = fail-closed）→ ②按**已验清单**定向 purge 残件（受保护树内全部 `__pycache__/` 与清单外 `*.pyc`——旧版本升级残留）→ ③文件哈希对称差。purge 判定**必须以已验清单为准**：若 purge 跑在验签之前，攻击者可用伪造清单把注入文件列成"预期"，purge 反而下留情。★Q8★ 精确规则：仅删"不在已验清单内的 `*.pyc` 与 `__pycache__/`"，其余清单外文件 fail-closed（合法 pyc 本就在清单内，不误删）；审计时序——purge 发生时 Python 未起，壳将 purge 事实经启动参数传给 applocal，bootstrap 后由 Python 侧补 `record_event(conn, 'shell', 'integrity_purge', ...)`，壳原生日志先行记录；
6. **签名重验节奏**（★R1-4★）：见 §4.2 侧车设计；节奏拍板项见 Q7。

### 4.4 失败路径

校验失败 → 复用现成中性错误页（与"固定端口被占"同一处理路径），fail-closed，不输出诊断细节（不给攻击者探测面）。

### 4.5 性能预算

| 项 | 数值 |
|---|---|
| 校验面总量 | ~20MB 分散在 20~30 次独立 SHA 操作（★R1-1★ 集合相等要求逐文件独立哈希，非单流；大头 python312.dll 7MB + python312.zip 7.4MB + deps.zip 5~8MB + 散件） |
| 实测参照（PowerShell Get-FileHash 逐件，含管道开销） | 291ms（仅占比参照，非 native 预期） |
| native 估算 | SHA-NI 单流 20MB ≈ 20~40ms；**冷启动**（页缓存未热）磁盘读放大 2~5 倍 → 真实 **60~150ms** |
| 占启动基线比例 | bootstrap ~8s → 热态 ~0.3%，冷态 ~1~2% |
| 启动性能反向收益 | pyc 构建期编译好，zipimport 直载——省现状"首次 import 现场编译写盘" |
| 验收门（★R1-1★ 放宽） | **冷态 <150ms 为验收上限，热态 <50ms 为目标值**；门值以 shell.cpp 冷/热双态实测后锁定，<50ms 不作为 blocker |
| 可选优化 | 大文件（dll/zip/deps.zip）间多线程并行哈希砍墙钟时间；暂不立项，实测超标再启用 |
| 取舍声明 | **runtime 自身（python312.dll/zip）保留在清单内**：patch python312.dll（hook marshal.loads）是比改 applocal 更强的 dump 捷径，移出校验面会让 RE 捷径复活——性能紧张时优先并行哈希，不缩减覆盖面 |

### 4.6 攻击面覆盖矩阵

| 注入路径 | 检测点 |
|----------|--------|
| 改 applocal 源码（`_core.py`/`_gate.py`） | 清单哈希失配 |
| 丢 `.pth` / sitecustomize / 新脚本 | 集合严格相等（清单外文件） |
| 伪造 `__pycache__` pyc（改字节码+伪 8 字节头） | 盘上无 pyc（收拢+`--no-compile`+零写入），伪造件=清单外文件 |
| 改 `python312._pth` | 清单哈希失配 |
| 松散 `fastapi.py` 影子模块 | 第一层：集合严格相等（boot 前拒绝）；第二层：path 收窄后 site-packages 不在 sys.path，无影子资格 |
| patch `.so/.pyd` | 清单哈希失配 |
| 改 deps.zip 内字节 | zip 条目哈希失配 |
| 环境变量注入（PYTHONPATH/PYTHONHOME/PYTHONSTARTUP） | ★R1-9★ `._pth` 存在即隔离模式，全部忽略（D5） |
| patch 壳 exe / 内存 dump | ❌ 残余口径（§6，具名缓解见 §9） |

---

## 5. 设计决策记录（为什么不是别的）

**D1 校验为何必须 native**：Python 侧自校验与被校验者同层，攻击者改 `_core.py` 时顺手把自检改恒真即破。壳 exe 是编译后机器码，在 site-packages 可写面之外，且已承担 spk 验签/keylib 配对——校验是同一信任根的延伸。

**D2 为何每次现算、不做缓存**：信任基础必须是"每次现算"而非"磁盘历史"；现状洞（解包缓存命中不复验）就是历史化的反例。成本可忽略（★R1-1★ 修正后预算：热态 <50ms、冷态 60~150ms，详见 §4.5），无需额外优化即可接受。

**D3 路线对比（甲：全量预编译进清单 / 乙：清单只含 .py+每启现场编译 / 丙：deps.zip 收拢）**：
- 乙的问题：每次启动多编译第三方源码（3~6MB，+0.3~1s 量级，用户判定影响性能）；
- 甲的问题：清单数千条、spk 膨胀、pack 流程多环节；
- **丙**：第三方树塌缩成 1 条哈希（清单 20~30 条）、pyc 预编译零每启编译、pyc 伪造物理不可能（zip 整体哈希）。先例：CPython 嵌入式发行版的 stdlib 即此模式（python312.zip 已在清单内）。

**D4 可重现构建**：`compileall --invalidation-mode=unchecked-hash`（pyc 头稳定）+ zip 条目时间戳钉死（固定 date_time/SOURCE_DATE_EPOCH）——两处都钉，deps.zip 哈希跨构建稳定，G5 式指纹不被破坏。★R1-7★ **所有产出 pyc 一律同规**：applocal 散件 pyc 与 deps.zip 内 pyc 同为 unchecked-hash + 确定性输入，否则 applocal/ 哈希跨构建漂移、清单反复失效。

**D5 path 收窄的双层价值**：第一层（集合严格相等）boot 前已拒绝影子文件；第二层（site-packages 不上 sys.path）防"壳被 patch、校验被 NOP"的残余路径上少一个面。纵深，非冗余。★R1-9★ 附带收益：`._pth` 存在即 Python 隔离模式，PYTHONPATH/PYTHONHOME/PYTHONSTARTUP 全部忽略——环境变量注入面顺带封死。

**D6 zipimport 兼容性**：★R1-10★ 技术前提列为**冒烟第一条断言**——3.12 zipimport 载无源 unchecked-hash pyc（无源时哈希字段被忽略直接加载，stdlib zip 分发即此先例）。zipimport 只给代码不给数据：helloApp 依赖集（fastapi/starlette/pydantic/uvicorn/h11/anyio）初判均为纯代码包、无 sibling 数据文件；applocal 为自有代码。运行时证据 = 现有冒烟链路（解包→healthz→登录页→接口）**外加显式断言：无 import site / sitecustomize / .pth 注入依赖**（★R1-5★ 防行为漂移，不是只跑 healthz）。未来引入带数据依赖的规则：数据随 zip 打包 + 强制 `importlib.resources` 读取。

**D7 完整性 ≠ 混淆**：见 §2 边界声明。

---

## 6. 三平台统一

**原则**：信任根 = native 引导件，校验永远发生在 Python 之前。平台差异只在引导件载体形态，不在校验逻辑。

| 组件 | Windows | Linux (M3) | Android |
|------|---------|------------|---------|
| native 引导件 | 壳 exe | launcher ELF（**同源 C，M3 必选**） | py-android 运行时 + 壳工程（已存在） |
| keylib | .dll | .so | .so（经 py-android） |
| 验哈希模块 | 平台无关 C，一份代码三处复用 | ← 同左 | ← 同左 |
| spk 验签 | 壳验签 | launcher 验签 | APK 签名承担（平台特性：包体不可变） |
| 清单格式 | 平台无关 | 平台无关 | 平台无关 |

- **Linux 设计约束（本次修订的关键）**："M3 无壳"假设作废——launcher ELF 从可选变必选，否则 Linux 是唯一没有 native 信任根的平台（连 spk 验签都没有 native 执行者）。P0 验哈希写成可移植模块，M3 直接复用。★Q6★ 验哈希模块（单 C 文件 + SHA-256）在 P0 期间即真机编译跑通，提前消 M3 风险；
- **Android 差异**：APK 签名 + 沙箱使包体只读（比逐件哈希更强）；残余 = 解包到 data dir 的运行期文件可被 root/调试注入，留 P2 与 keylib 纵深一起收口（口径与壳被 patch 同级）；
- **P1/P2 天然平台无关**（在 pkapp 工具链侧），一次落地三平台生效。

---

## 7. 改动面（文件级）

| 模块 | 改动 |
|------|------|
| pkapp/pkapp/commands/package.py | 清单生成；staging 期 compileall + deps.zip 打包（时间戳钉死）；spk 头 `format_version=2`（★Q2★） |
| pkapp/pkapp/packager/（assemble/unpack 链） | spk 携带固化环境；unpack 退化为拷文件（**语义变化，见 Q2**）；升级清残 purge（★R1-3★，见 Q8）；清单签名侧车生成（复用 spk 密钥对） |
| pkapp/pkapp/packager/（校验实现合同） | ★R1-2★ 校验 = 递归枚举受保护树 → `{相对路径: hash}` 对称差，**禁止**实现成清单逐条 stat |
| pkapp python312._pth | 改为 packager 按依赖集生成（path 收窄） |
| shell-windows/src/shell.cpp | 验哈希模块（可移植 C，复用 SHA-256）+ PyConfig `write_bytecode=0` + 读同级 `integrity.manifest(.sig)`（exe 目录基准）+ `supported_format_max=2`（★Q7/Q2★） |
| scripts/vendor.py | 无需独立改造：applocal wheel 仅作构建期输入，pyc 由 staging compileall 统一产出（原 P0.5 并入） |
| 测试 | 四路注入 fail-closed 用例 + 三平台冒烟 + 启动增量门 |

---

## 8. 验收标准

1. 四路注入全部 fail-closed：篡改 `_core.py` / 丢 `.pth` / 伪造 pyc / 改 `._pth`（另加：影子松散文件、patch `.so`、改 deps.zip）；
2. 正常启动回归绿 + 三平台冒烟（helloApp healthz / 登录页 / 接口）；
3. 启动校验增量：**冷态 <150ms 验收上限、热态 <50ms 目标值**（门值以 shell.cpp 冷/热双态实测锁定，与 §4.5 一致，★R2-1★）；
4. 可重现构建：同源码两次构建**所有产出**（deps.zip + applocal 散件 pyc）哈希一致（G5 兼容，与 ★R1-7★ 口径对齐，★R2-5★）；
5. 格式迁移与清残（★Q2/Q8★）：新壳拒读旧 spk（无侧车，fail-closed）；新 spk 在旧壳上因无 wheels 段 unpack 失败；旧版残留 `__pycache__` 升级后被定向 purge 且正常启动绿，审计事件 `integrity_purge` 落库。

---

## 9. 残余风险与不做清单

- 壳二进制被 patch → ★R1-8★ 具名缓解升级：Windows 壳 exe 走 Authenticode 签名 + OS 校验；Linux M3 launcher ELF 经分发/包管理器签名校验；Android APK v2 签名背书。自检为纵深。口径从"标残余"升级为"有平台签名机制承担的残余"；
- 运行期内存 dump（1A）→ §1 边界外；
- 服务器 root / 物理访问 → §1 边界外；
- **部署权限分离** → "游戏结束"级威胁的运维缓解正式化：应用目录与运行账号最小权限、服务账号与部署账号分离、（Linux）部署目录 owner 非应用运行账号——与平台签名共同收敛该级威胁（不消除，抬高实施条件）；
- 目录权限只读（Linux 部署 chmod）→ 作为部署建议写入文档，**不承担**信任根职责（owner 可改即失效）。

---

## 10. 拍板记录（Q1-Q8，2026-10-07）

全部拍板完毕，正文与拍板结论一致，可开工。

- **Q1 deps.zip 落位 = `site-packages/deps.zip`**：与 `._pth` 收窄条目一致，零新增 sys.path；独立 `_deps/` 收益小、多一条 path，不做。
- **Q2 版本迁移 = spk 格式升版 1→2 + 双向拒绝 + 原子交付**：
  - 新 spk 头写入 `format_version=2`（固化环境 + 侧车）；壳内嵌 `supported_format_max=2`；
  - **新壳读旧 spk（format 1，无侧车）→ 拒绝启动**（无法验清单，fail-closed）；
  - **旧壳读新 spk → 拒绝**：旧壳无 `format_version` 概念，实际拒点是"新 spk 无 wheels 段 → 旧壳 unpack 流程失败 fail-closed"；`supported_format_max` 显式检查自本版起成为壳的正式合同（对建议表述的技术修正）；
  - shell 与 spk 为同一更新单元**原子交付**（Windows 包内 exe 与 spk 同 zip，天然原子）；**不做双格式兼容**——双格式 = 壳保留"无校验旧路径"，扩大攻击面；
  - `min_pkapp_version` 同步升版；**存量旧包（旧壳+旧 spk）不追溯**，维持现状运行，新版本起生效。
- **Q3 Android = 不进 P0**，边界写死："APK 签名承担包体完整性 / data dir 运行期校验归 P2"——避免 P2 排期时被追溯为 P0 漏洞。
- **Q4 zipimport 数据依赖 = 默认"数据随 zip + `importlib.resources`"**；仅当依赖确需 writable/非代码 sibling 文件时升级为整目录散件化（冒烟 R1-10 发现即触发）。
- **Q5 doctor = 纳入**：`pkapp doctor --integrity`，**复用同一份可移植验哈希模块**（不是重写），运维离线审计已部署包，无需启动应用。
- **Q6 Linux launcher = P0 期间跑通真机编译**：验哈希为单 C 文件 + SHA-256，早期编译消 M3 风险成本极低；§6 已定为必选，早验证早排雷。
- **Q7 侧车节奏 = 锁死签名侧车**（放弃每启全量 spk 验签；安全性质等价，成本几 KB 毫秒级）。补两条实现约束：
  - **密钥复用**：清单签名复用现有 spk 验签密钥对，壳内嵌验签公钥与 spk 验签同一枚——不引入第二把密钥，不扩密钥管理面；
  - **读取合同**：壳在 `write_bytecode=0` 之后、`PyRun` 之前，以自身 exe 所在目录为基准读取同级 `integrity.manifest` + `integrity.manifest.sig`。
- **Q8 清残策略 = 锁死定向 purge**，精确规则（防误删合法件）：
  - 验清单签名通过后：受保护树内**凡不在已验清单中的 `*.pyc` 与 `__pycache__/`** 一律删除；**其余一切清单外文件**（`.py`/`.pth`/松散模块/patch 的 `.so`）仍 fail-closed；
  - 合法 pyc（applocal 散件、散件发行版）本就在清单内，不误删；被清者仅为"旧版残留 pycache"这类已知安全形态；
  - **审计落库时序修正**（对建议的技术修正）：purge 发生在 native 侧、Python 未起——**不能直接调 `record_event`**。落地：壳将 purge 事实（计数/路径列表）经启动参数传给 applocal，bootstrap 起来后由 Python 侧补 `record_event(conn, 'shell', 'integrity_purge', ...)`；壳原生日志（boot-timing 通道）同步先行记录，防 Python 未起即崩时丢证据。
