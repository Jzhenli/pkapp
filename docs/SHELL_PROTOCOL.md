# SHELL_PROTOCOL.md — 协议 A 事实源（壳 ⇄ applocal）
**版本**：v1.2（v1.1 契约复核补丁 + ★applocal 复核修复同步：静态豁免面补 HEAD★，明细见 §13）
**地位**：本文件是**三份壳模板与 applocal 之间契约的唯一事实源**。任何壳/applocal 的行为差异，以本文件为准；改动需同时更新 §末尾变更记录与三份壳契约测试。
**约束**：**壳 = dumb loader**（只做"让一个可信的 Python 在正确的位置醒来"），不得理解 app 语义。

---
## 1. 适用范围与判据
### 1.1 三条裁决判据（设计原理锚点）
```
① 时序判据：必须在解释器存在之前完成的事，只能由壳承担
            （env 设置、解压、加载前文件操作、单实例互斥、验签）。
② 信任判据：决定"是否运行这段代码"的逻辑必须独立于被验证代码。
            验签不能住在被验签的 site-packages 里。
③ 失败域判据：被检测对象可能故障时，检测者须在故障域之外。
            展开区自检不可行（DLL 坏死时 import 即死）；
            stdio 重定向必须覆盖 Py_Initialize 之前的窗口期。
```
### 1.2 反向边界（**留在 applocal，壳不得越界**）
| 事项 | 归属 | 理由 |
|---|---|---|
| `sys.path` 追加 `app/` | applocal | 发生在 Initialize 之后 |
| token 中间件与 `/auth`、`/healthz`、静态豁免 | applocal | HTTP 层 |
| 心跳 touch（写 ready） | applocal | 只有 uvicorn 所在进程能探测 uvicorn；壳只消费 ready |
| migrate 与路径服务 | applocal | 运行期职责 |

---
## 2. 环境变量契约（壳 → applocal）
**规则**：壳在 `bootstrap()` **之前**全部设置完毕；applocal 只读，**缺失即契约违例**（除备注标注 **optional** 者——有缺省值的按缺省，★v1.1 与 applocal 实现对齐★）。所有路径为**绝对展开后路径**。

| 变量 | 含义 | Windows 示例 | 备注 |
|---|---|---|---|
| `MYAPP_PLATFORM` | 平台标识 | `windows` \| `android` \| `linux` | 决定 `so` 注入与 setproctitle 行为 |
| `MYAPP_DATA_DIR` | 用户数据区（跟着用户走） | `%LOCALAPPDATA%\MyApp\data\` | 绝不写只读区 |
| `MYAPP_CACHE_DIR` | 缓存区（log/、ready、diag 落此） | `%LOCALAPPDATA%\MyApp\cache\` | 可整删，删后须自愈 |
| `MYAPP_LOG_DIR` | 日志目录 | `…\cache\log\` | **optional**，缺省＝`MYAPP_CACHE_DIR/log`；壳消费（stdio 落盘 §7），applocal 仅解析 |
| `MYAPP_READY_FILE` | ready 文件绝对路径 | `…\cache\ready` | 见 §5 |
| `MYAPP_DIAG_FILE` | diag 文件绝对路径 | `…\cache\diag.json` | 见 §9 |
| `MYAPP_STATIC_DIR` | Vue 产物目录（dist） | `…\runtime\dist\` | **恒存在** |
| `MYAPP_PORT` | **端口偏好**，非最终值 | `8765` 或 `0`（＝自选） | **optional**，缺省 `0`＝自选。⚠ 壳**禁止**假设实际端口＝此值（实际端口以 ready 为准） |
| `MYAPP_VERSION` | 版本号 | `1.4.2` / dev 下 `0.0.0-dev` | |
| `MYAPP_MANIFEST_PATH` | 展开区 manifest 路径 | `…\runtime\manifest` | applocal 只读；**禁止用其做安全决策**（信任源是壳的验签） |
| `MYAPP_TOKEN` | 每次启动重新生成的 bearer token | 32 字节随机 | **optional**（dev 非严格旁路可缺省；embedded／strict 下必须）。禁止进 URL / 日志 |
| `MYAPP_HANDSHAKE_FILE` | ★v8.1 实现期补充★ 一次性握手码文件路径 | `…\cache\handshake` | **optional**（embedded 必须；dev 严格模式由 `pkapp dev` 注入）。壳每次导航前重写；applocal 只读并**用后作废** |
| `MYAPP_NATIVE_LIB_DIR` | 原生库目录（Android：APK `lib/<abi>/`） | `/data/app/…/lib/arm64` | **optional**（桌面端缺省空串） |
| `MYAPP_STRICT_AUTH` | `1`＝启用生产同款鉴权 | `pkapp dev --strict-auth` 置 1 | **optional**（dev 缺省 `0`）；★v1.1★ **embedded 三壳必须置 1**——忘设即 loopback 裸奔（§12.2⑧ 断言） |

**dev 契约**（`pkapp dev`）：platform＝宿主平台、data/cache/static＝项目 `.dev/` 下、port＝`8765`、version＝`0.0.0-dev`、manifest＝`{}`（空 dict，非缺失）、static_dir 走官方容错模板。

**app/ 目录定位（★v1.1 明文化★）**：无独立环境变量——applocal 派生为 `MYAPP_MANIFEST_PATH` 同级 `app/`（§3.1 同构布局）；bootstrap 将其**追加到 sys.path 末尾**（stdlib/依赖优先，防用户目录同名模块 shadow 标准库——已实证）。

### 2.1 ★v8.1 V15（M0 D2 真机实测发现）★ `sys.path` 上多出来的可执行文件目录
在真实运行时上实测（python-build-standalone 3.12.14 + 本仓库生成的 `_pth`）：
```
$ python.exe -I -c "import sys; print(sys.path)"
[...\python312.zip, ...\DLLs, ...\site-packages, ...\<可执行文件所在目录>]
```
即使 `-I`（且 `_pth` 触发 `isolated=1`），**Windows 仍会把 executable_dir 追加到 `sys.path` 末尾**，机制与 `_pth` 无关。
⇒ **embedded 情形下该目录＝安装目录 `MyApp\`**（不是展开区），因此：
```
① 安装目录严禁出现任何 *.py / 包目录 / DLLs 目录 —— 它们会被直接 import 并可能劫持名字；
② 本事实叠加 B.t 禁令：安装目录也不得出现 <EXE-stem>._pth；
③ 最终顺序：python3XX.zip → DLLs → site-packages → <安装目录> → app/（app/ 由 bootstrap 追加，用户代码最后）。
```
⇒ packager 与 `pkapp doctor` 须断言安装目录洁净（★v1.1 引用澄清：G10 编号定义在 `PACKAGER_SPEC.md` §9（v0.2 回填），本断言的实现条款为协议 B **B.t③**）。

---
## 3. 壳职责九步（Windows；另两端按 §10 对账）
```
0. 单实例互斥（仅 Windows）★v8.0 R21★
   HANDLE m = CreateMutexW(nullptr, TRUE, L"Local\\MyApp-<appname>-instance");
   GetLastError()==ERROR_ALREADY_EXISTS → 激活首实例窗口后 return 0
   ★互斥必须覆盖"验签 → LoadLibrary"全程★；键名含应用名，防跨应用误锁
1. 验签（成包/破损/版本不符 → 直接渲染错误页）★含 v8.1 V9 版本单调性★
2. 指纹比对 / 决定全量解压或 delta
3. 预清理旧 ready 与旧握手码文件（避免读到上一进程的存活假象 / 陈旧码；★v1.1 增后者★）
4. 设置环境变量（含新生成 token）
5. stdio 重定向（覆盖 Initialize 前窗口期）
6. 加载解释器 LoadLibraryEx(manifest.python_dll, LOAD_WITH_ALTERED_SEARCH_PATH)
7. ★v8.1★ LoadLibrary 成功后才写 runtime.version 记账（指纹规则 ③′）
   ——只有真正加载成功的展开区才被记账，杜绝"半状态被指纹洗白"
8. import applocal; bootstrap(manifest.entry)
   ★v1.1：entry 经 manifest.entry 传递（协议 B §3.3），禁止壳内硬编码——同 python_dll 键模式★
   ★返回后立即 PyEval_SaveThread()，主线程永不持有 GIL（V1，致命）★
8.5 等待 ready（★v1.1★）：bootstrap 返回 ≠ 端口已监听；首见 ready=true 且读到 port 才导航
    （URL 附一次性握手码）；超时（默认 120s，AppSpec 可调）→ 读 diag.json 渲染错误页
9. 每次主框架导航时重写握手码
   ★v1.2 语义修正：重写为导航 URL 所附码（?handshake= 原样入文件），无码导航才写新随机码作废未用码。
   原文"无条件重写新码"与 8.5 自相矛盾——壳自身导航也触发步骤 9，URL 码≠文件码，页面 /auth 恒 403。
   副作用：同 URL 重载（F5）码重新入文件可再次握手；一次性消费语义不变（服务端验过即删）。★
```

---
## 4. 目录契约（四铁律）
1. 只读区（展开区）随时可整删重建，**严禁覆盖式解压**；
2. 用户数据绝不进只读区，路径只经 `applocal.paths`；
3. 路径钉死为展开后绝对路径——载体：Windows/Linux `_pth`，Android PyConfig/JNI；
4. Android：so 走 `lib/<abi>/` 系统 dlopen（W^X 强制）。

---
## 5. ready 文件契约（★v8.1 V6/V7 定稿★）
**文件路径**：`MYAPP_READY_FILE`（cache_dir 下，与展开区解耦）
**内容**（单个 JSON 对象，原子写入 tmp+rename）：
```json
{"ready": true, "port": N, "pid": P, "seq": S, "ts": T}
```
| 字段 | 语义 |
|---|---|
| `ready` | applocal 完成自检（`/healthz` 真实请求成功）后置 true |
| `port` | **实际监听端口**——壳只能从这里取，禁止假设 AppSpec 常量 |
| `pid` | 进程标识；三端同进程架构下＝壳进程自身 pid，实为陈旧 ready 排查字段（"是不是我起的"由步骤 3 预清理保证；★v1.1 措辞修正★） |
| `seq` | 单调递增计数（每心跳 +1）→ **判活主判据** |
| `ts` | 墙上时间戳，仅供人工排查；**不作判死依据** |

**为什么不只用 mtime**：工控机 RTC 掉电 / 用户改系统时间会让 mtime 判死误杀或永不判死；`seq` 由本进程自增，不依赖墙上时钟。mtime 降级为辅助判据。

**判死（壳侧）★v1.1：分档与计时起点★**：
```
运行期（首见 ready 之后）：
  seq 在 30s（5s/次，容忍 5 次丢失）内无增长
  OR ready 文件消失（★"曾出现过"前提——v1.0 文本缺失，按字面会把冷启动误杀；
     Android cacheDir 被系统清除属此情形）
  OR ready{false}
冷启动期（bootstrap 返回后、尚未首见 ready）：
  计时起点＝bootstrap 返回——壳轮询定时器随主线程消息循环自然启动，
  ★禁止改为独立轮询线程★（那会把大依赖慢启动 import 误杀在 30s 内）；
  超时独立档：默认 120s（AppSpec 可调）→ 渲染"启动失败"错误页
→ 一律读 diag.json → 错误页 / 可重启；Linux 除外，走 L0/L1/L2（§10.3）
```

---
## 6. 探测式心跳（applocal 侧）
```
每 5s：向自身 http://127.0.0.1:{port}/healthz 发真实请求（超时 2s）
  成功 → seq += 1，touch ready（原子写）
  失败/hang → 不 touch → 壳 30s 超时判死
  ★v1.1★ 连续 2 拍失败 → 写一次 diag("runtime")（此后不刷盘）——
  uvicorn startup 失败（端口被抢/ASGI 异常）时错误页有因可查
```
理由：只有 uvicorn 所在进程能真实探测 uvicorn 是否还在服务；`is_alive()` 类判断对死锁 hang 无效。

---
## 7. stdio 重定向条款（★v8.1 V8 修订★）
**必须做全套，不得只依赖 CRT 层 `freopen`**——壳与 `python3XX.dll` 若非同一 CRT 实例（/MT vs /MD、版本不同），两侧 `stdout` 是互不相干的 FILE*，重定向**静默失效且无任何报错**。
```c
h  = CreateFileW(log, FILE_APPEND_DATA|FILE_SHARE_READ, FILE_SHARE_READ, ...);
SetStdHandle(STD_OUTPUT_HANDLE, h);
SetStdHandle(STD_ERROR_HANDLE,  h);
int fd = _open_osfhandle((intptr_t)h, _O_TEXT|_O_APPEND);
_dup2(fd, 1); _dup2(fd, 2);
setvbuf(stdout, NULL, _IONBF, 0);
```
其他：GUI 子系统 stdout 是黑洞，本条款是唯一观测手段；日志**按天轮转留 7 份**；uvicorn `access_log=False`（避免每请求刷盘）。
**CI 断言用例**：在 `Py_Initialize` 之前故意 `printf("PRE-INIT-PROBE")`，断言该行出现在日志文件中。

---
## 8. 握手鉴权
```
壳：等待 ready 后加载 http://127.0.0.1:{port}/?handshake=<一次性握手码>（每次导航重写）
前端：带握手码 POST /auth → 换回 token
后续请求：X-MYAPP-Token: <token>
豁免（★v1.1 精确化——豁免面即鉴权边界，必须条款化★）：
  ① 静态资源：dist 内实存文件（GET/HEAD；★v1.2★ HEAD 与 GET 同一豁免规则——同一资源不得因方法
     不同就要 token，且 HEAD 暴露的不过是 GET 已有的响应头；applocal 回响应头、body 置空，
     content-length 仍为实体长度）；
  ② SPA 路由兜底：GET 静态未命中且 Accept 含 text/html → 兜底 index.html（亦豁免）。
     依据：浏览器导航 Accept 含 text/html，fetch/XHR 的 API 调用不含——API 无法借道绕过 401；
  ③ /auth 本身；④ /healthz（本地探测）
禁止：token 进 URL、进日志、进 diag.json 字段值
静态缓存头（★v1.1★）：index.html 必须 no-store（防升级后 WebView 缓存旧入口 → 白屏/404）；
带内容 hash 的 assets 可长缓存。applocal 静态分支按此实现
dev：MYAPP_STRICT_AUTH=0 默认旁路（免打扰）；
     pkapp dev --strict-auth → MYAPP_STRICT_AUTH=1，启用生产同款中间件+握手端点，
     暴露"忘带 X-MYAPP-Token 头"这类只在 embedded 爆的 401 bug
```

---
## 9. diag.json 与失败渲染
```json
{"stage": "verify|extract|fingerprint|load|bootstrap|runtime",
 "error": "人类可读摘要",
 "detail": "本机可读的堆栈/errno（禁止含 token）",
 "recoverable": true,
 "ts": 1234567890}
```
**渲染规则**：ready{false} / 验签失败 / 解压失败 / 加载失败 → 一律读 diag.json 渲染错误页，**绝不黑屏**；`recoverable=true` 时提供"重启"按钮。

---
## 10. 三端差异与职责投影（职责同、实现异）
### 10.1 Windows（zip 分发）
壳＝**可信组装器**全责：单实例互斥、验签、解压、记账、LoadLibrary、WebView、心跳轮询。
### 10.2 Android（APK 分发）
壳退化为**引导器**（第三方无法就地改写 APK 内容）：
验签由 APK 签名承担、原子性由 PackageManager 承担、单实例由 launcher 保证；
壳剩余职责：assets 解压 → JNI 引导 → WebView → 心跳轮询。
**★v8.1 R23★**：所有 native 产物须满足 Android 15+ **16KB 页对齐**（ELF 段 + `zipalign -P 16`），构建期自检。

**★v1.3 M2 实测落地注记（shell-android/，Magic6 Pro 验证）★**：
```
① sys.path 四条目（PYTHONPATH 启动契约，JNI setenv 后 Py_InitializeEx(0)）：
     stdlib.zip : <files>/runtime/site-packages : <files>/runtime 根 : nativeLibraryDir
   - nativeLibraryDir 必须在列：扩展模块（_struct/_hashlib…）经 urllib→base64→struct
     import 链在 bootstrap 前就需要；bootstrap 内 _inject_native 来不及
   - runtime 根必须显式在列：Windows 的 `import app.main` 依赖 _pth "import site" 行
     的 site.getsitepackages() 把 sys.prefix（=_pth 同目录）隐性入 path；Android
     Py_NoSiteFlag=1 无 site 处理，缺它必报 "No module named 'app'"
② 扩展模块 W^X 形态：bundle modules/*.so 平铺进 jniLibs/<abi>（→ nativeLibraryDir，
   走系统 dlopen，绝不从可写目录加载）；_inject_native 仍做 RTLD_GLOBAL 预载
③ 后台冻结（MagicOS 实测）：切后台约 1s 整进程冻结（FGS 不能免），心跳/线程暂停，
   回前台立即恢复。壳必须 onResume 重置判死宽限窗——冻结期间 uptimeMillis 照走，
   >30s 后台回前台首拍会误判死出假错误页
④ 握手镜像 ★v1.2★ 语义在 shouldOverrideUrlLoading：URL 带码→镜像入文件；无码→新随机码
```
### 10.3 Linux（部署目录 + 符号链接）
壳＝**铺好 env 然后 exec 消失**（~25 行 bash + systemd 模板）。exec 拿走了壳的监测福利 → **R20 三档**：
```
L0：只 systemd 的 Restart=on-failure（进程崩溃可观测，hang 不可观测）
L1：外部 watchdog 定时探 /healthz（额外进程，需部署）
L2：接受 hang 不可检测（显式取舍，登记）
```
### 10.4 进程标识三端契约
| 平台 | 契约 |
|---|---|
| Windows | 进程名＝`MyApp.exe`（任务管理器显示应用名） |
| Android | package name / label |
| Linux | `myapp`（`exec -a` + 可选 setproctitle 探测，缺失静默跳过） |

---
## 11. 线程模型四条（Windows 壳，★v8.1★）
```
① PyRun_SimpleString 要求调用者持 GIL 且返回后不释放（本机实证 PyGILState_Check()==1）
   ⇒ bootstrap 返回后必须立即 PyEval_SaveThread()；之后主线程永不持有 GIL
   ⇒ 导出由此 3 → 4：Py_Initialize / Py_IsInitialized / PyRun_SimpleString / PyEval_SaveThread
   ⇒ 其余回调（定时器/窗口过程）进 Python 须 PyGILState_Ensure/Release 配对
② 退出走 ExitProcess，不做 Py_Finalize（uvicorn 后台线程下 Finalize 是经典死锁源）
③ 重启流程 = ExitProcess(非零) + 外层（可选）看门狗
④ 嵌入态派生受限（R25）：bootstrap 第 0 步自行设置 sys.argv
   （sys.executable 由嵌入初始化给出，M0 D2 实测确认；★v1.1 与实现对齐：applocal 只设 argv★）；
   multiprocessing 默认 spawn 与 uvicorn --reload 不可用，dev 侧禁 reload
```
**★v8.1 V2 否决★**：不采用 `python3.dll`（稳定 ABI 代理）——实测其**不导出 `PyRun_SimpleString`**，且版本绑定会引入"加载到系统里另一个 Python"的不确定性。

---
## 12. 测试形态
### 12.1 契约测试（env 模拟，无真机）
applocal 侧注入不同 `MYAPP_*` 组合，断言：路径解析、**缺失必填变量即抛出 ContractError**（optional 变量按缺省值解析，★v1.1★）、`dev` 与 `embedded` 同一契约、ready schema 字段齐全与 seq 单调递增、端口偏好被占时回落 OS 分配且**实际端口写回 ready**（★v1.1 措辞修正★）。
### 12.2 三壳一致性测试（同一份断言跑三个壳）
```
① 九个步骤齐全且顺序正确（含互斥与 ③′ 记账时机）
② ready 字段齐全，port 与实际监听一致
③ 杀进程 → 30s 内被感知；注入 hang → 30s 内被感知
④ 三种失败路径均读 diag.json 渲染，无黑屏
⑤ 双开第二实例激活首实例，展开区零损坏（Windows）
⑥ /auth 换 token 后带 X-MYAPP-Token 通过、不带 401
⑦ 进程标识符合 §10.4
⑧ embedded 模式 MYAPP_STRICT_AUTH=1 已设置（★v1.1 防裸奔断言★）
```
**★v1.3 实现状态★**：①–⑧ Windows 全量（shell-windows/tests，15 例差分）；Android 落地外部可观测子集
（shell-android/tests/test_shell_contract_device.py，8 例真机回归：ready schema/心跳单调/strict_auth
401/握手错码 403/正链 token+API/码用后作废/九步锚点/前后台存活与恢复）——验签子集按 §10.2 由
APK 签名承担，跳过；⑤⑦ 属 Windows/Linux 形态。Linux M3。

---
## 13. 变更记录
| 版本 | 内容 |
|---|---|
| v1.0 | 依据 v8.0 §5 建立；纳入 v8.1 补丁：ready schema 与 seq 主判据（V6/V7）、stdio 双保险（V8）、GIL 归还与第 4 导出（V1）、python3.dll 否决（V2）、16KB 对齐（R23）、派生能力限制（R25） |
| — | §5.1 环境变量表、§4.4 十二 API 由本 v1 依正文重新确立；如与 v7.x 历史讨论冲突，**以本文件为准** |
| v1.1 | ★契约复核补丁（applocal 0.1.0 实现对账，零机制变更）★：§2 补 optional 标注并与实现必填集合对齐（LOG_DIR/PORT/TOKEN/HANDSHAKE_FILE/NATIVE_LIB_DIR/STRICT_AUTH）；entry 经 manifest.entry 传递（步骤 8 禁硬编码，同 python_dll 键模式）；§2.1 悬空引用 "G10" 改指 B.t③；步骤 3 预清理增握手码文件、插步骤 8.5"等待 ready 再导航"；§5 判死分档（计时起点＝首见 ready、冷启动独立 120s 档、ready 消失补"曾出现过"前提）、pid 备注修正；§8 豁免面精确化（SPA 兜底）+ 静态缓存头（index.html no-store）+ embedded 必设 STRICT_AUTH=1；§11④ sys.argv 措辞对齐实现；§12.1 端口措辞修正；§12.2 增⑧；applocal 0.1.0 代码复核修复同步：§2 明文 app/ 目录派生规则（manifest 同级、sys.path 末尾追加）、§6 心跳连续 2 拍失败写 diag |
| v1.2 | ★applocal 复核修复同步（零机制变更）★：§8① 静态豁免面补 **HEAD**（GET/HEAD 同一豁免规则；applocal 侧：HEAD 只回响应头、body 置空、content-length 为实体长度）。理由：嵌入端探测方拿不到 token，同一资源 GET 豁免而 HEAD 401 属规则漏洞而非有意设计；豁免面即鉴权边界，故条款化。同步三壳契约测试断言：HEAD dist 内实存文件在 strict 下亦豁免。另有步骤 9 握手镜像修正：壳自身导航带码时镜像入文件，仅无码导航写新随机码（URL 码≠文件码 → /auth 403 实证） |
| v1.3 | §10.2 Android M2 落地注记（sys.path 四条目契约 / jniLibs W^X / MagicOS 后台冻结与 onResume 宽限重置）；§12.2 Android 真机契约子集 8 例（shell-android/tests） |
