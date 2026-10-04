# shell-android — pkapp Android Kotlin 壳 ★v8.5★

协议 A（v1.3）的 Android 实现。壳 = **引导器**（§10.2 投影：验签由 APK 签名承担、
单实例由 launcher 承担、原子性由 PackageManager 承担），剩余职责：assets 解压 →
JNI 引导 CPython → WebView → 心跳轮询。本目录是 M2 交付物，对应方案 v8 §5.5 四阶段路线中的 Android 壳。

**事实源**（行为差异以文档为准）：

| 文档 | 地位 |
|---|---|
| `docs/SHELL_PROTOCOL.md`（v1.3 §10.2） | 壳 ⇄ applocal 契约唯一事实源 + Android 落地注记 |
| `docs/PACKAGER_SPEC.md`（v0.4） | spk 打包格式 |
| `docs/pkapp打包方案v8.md` §5.5 | 总体路线 |

> 本文 bat 示例统一用 `%REPO%` 指仓库根；复制前先 `set "REPO=<仓库根路径>"`。

## 目录结构

```
shell-android/
├── build.bat                     # 一键构建（设置 toolchain env 后转发 gradle）
├── d1-spike/                     # D1 硬闸遗留：JNI 引导最小验证（九步配方来源）
├── shell/                        # gradle 工程根
│   ├── settings.gradle.kts / build.gradle.kts / gradle.properties
│   └── app/
│       ├── build.gradle.kts      # abiFilters / useLegacyPackaging / noCompress "spk"
│       ├── src/main/
│       │   ├── AndroidManifest.xml   # singleTask + configChanges 全收 + BootService FGS
│       │   ├── cpp/engine.c          # JNI 引擎：env 应用→Py_InitializeEx(0)→bootstrap→SaveThread
│       │   ├── java/com/pkapp/shell/
│       │   │   ├── MainActivity.kt   # 解压→env→engineBoot→ready tick→WebView+握手镜像
│       │   │   ├── BootService.kt    # 前台服务（specialUse：embedded-python-local-server）
│       │   │   └── ShellLog.kt       # logcat+文件双写，按天轮转留 7 份
│       │   └── res/              # network_security_config（仅 127.0.0.1 明文）+ 图标
│       └── build/outputs/apk/debug/app-debug.apk   # 构建产物
│
│   # assets/ 与 jniLibs/ 不入仓库（★方案A★ 裸模板）：package 时 android_shell.py
│   # 按指纹物化到 <PKAPP_CACHE>/shells/android/ 并从托管快照注入（lib 前缀契约
│   # + stdlib.zip ZIP_STORED + runtime.spk 拷入）
└── tests/
    └── test_shell_contract_device.py   # 8 例真机契约回归（§12.2 外部可观测子集）
```

## 构建（★v8.5★ 两条命令版，★方案A★ 裸模板+构建期注入）

前置：toolchain 就位（JDK17 + SDK 35 + NDK 27）——推荐 `pkapp fetch android` 托管缓存
（JDK/Gradle/SDK 五组件/py-android 运行时一次到位，licenses 自动落盘）；或手工布置
`%PKAPP_ANDROID_TOOLCHAIN%\{jdk\jdk-17.0.20.1+1,android-sdk,gradle-8.9,gradle-home}` 整体根
（见 `shell/build.bat`）。

```bat
:: 构建 spk + 打 APK（cwd=项目目录；applocal 不在 PyPI 需 PIP_FIND_LINKS）
:: 解释器件（jniLibs/stdlib.zip）无需预铺设——package 时按指纹物化模板并从托管
:: 快照注入（android_shell.py）；快照缺失时报错指向 `pkapp fetch android`
cd /d <项目目录>
set PIP_FIND_LINKS=%REPO%\out\e2e\wheels
%REPO%\.venv\Scripts\pkapp.exe build android
%REPO%\.venv\Scripts\pkapp.exe package android
:: 产物：<项目>\release\helloworld.apk（spk 拷入 assets / touch 防增量漏拷 /
:: gradle / APK 内 spk 字节校验全部内建，增量漏掉即构建失败而非真机白屏）
:: 16KB 对齐自检：zipalign -c -P 16 4 <release>\helloworld.apk
```

## 九步职责投影（§3 → Android 形态）

| 协议步骤 | Windows 实现 | Android 实现 |
|---|---|---|
| 0 单实例 | 命名互斥体 | launcher/singleTask |
| 1 验签 | Ed25519 + spk_hash 重算 | **APK 签名**（assets 随 APK 整体被 v2 签名覆盖） |
| 2 指纹解压 | staging→原子 rename | ZipInputStream 流式 + zip-slip 防护 + staging→runtime.old 让位→rename→记账 runtime.version |
| 3 预清理 | ready/握手码删除 | 同（cache 下） |
| 4 env | SetEnvironmentVariable | JNI 前逐条 setenv（16 条 MYAPP_* + PYTHONPATH 四条目） |
| 5 stdio | _wfreopen 双保险 | pipe+pump 线程→logcat+文件双写（raw read(fd)） |
| 6 LoadLibrary | LoadLibraryExW | System.loadLibrary("engine")（libpython 由 engine 链接拉起） |
| 7 记账 | runtime.version 写入 | 同（指纹命中跳过解压） |
| 8 bootstrap | PyRun_SimpleString | PyRun_SimpleString("import applocal; applocal.bootstrap(entry)") |
| 8.5 等 ready | WM_TIMER 轮询 | 主 looper Handler tick（500ms） |
| 9 握手导航 | Navigate 前写文件 | loadUrl("?handshake=码") + ★v1.2★ 镜像于 shouldOverrideUrlLoading |

**PYTHONPATH 四条目**（★v1.3★，见协议 §10.2①）：`stdlib.zip : runtime/site-packages : runtime根 : nativeLibraryDir`。

## 线程模型（§11 Android 投影）

1. **boot 在后台线程**（Android 有 ANR，不能像 Windows 阻塞主线程）；ready 轮询恒在主 looper Handler（协议禁独立轮询线程的 Android 对应物）。
2. **V1 致命条款同款**：engine.c bootstrap 返回后立即 `PyEval_SaveThread()`；onPause 回调经 `PyGILState_Ensure/Release` 配对进 Python（`applocal.on_background()`）。
3. **心跳在 applocal 后台线程**（探测式，§6）；壳只消费 ready。
4. 退出 = `Process.killProcess(Process.myPid())`，不做 Py_Finalize。

## 真机契约测试（8 例）

```bat
:: 前置：在线设备 + app-debug.apk 已装（无线调试连接见下）
cd /d %REPO%\pkapp
%REPO%\.venv\Scripts\python.exe -m pytest ../shell-android/tests/test_shell_contract_device.py -q
```

覆盖：ready schema 五键 / 心跳 seq 单调 / strict_auth 401 / 握手错码 403 /
握手正链（token→/api/hello 200→码用后作废）/ 九步锚点在案 / 前后台存活与恢复 /
**>30s 长后台不假死**（onResume 宽限重置回归）。无设备或未安装自动 skip。

## e2e 手工复现（无线调试）

```bat
:: 1) 连接（荣耀 MagicOS：USB 不可靠，走无线调试；配对一次后只需 connect）
adb mdns services                 :: 发现 <serial>._adb-tls-connect._tcp → IP:port
adb connect 192.168.124.x:port    :: 端口以手机「无线调试」页面实时显示为准（轮换）
adb devices                       :: 必须恰有一个 device（mdns 自动注册项会重复，disconnect 清理）

:: 2) 安装启动
adb install -r <项目>\release\<name>.apk
adb shell am start -n com.pkapp.shell/.MainActivity

:: 3) 观察锚点（九步全绿判据）
adb shell run-as com.pkapp.shell cat files/cache/log/shell-YYYYMMDD.log
:: 期待：load spk begin → spk loaded, manifest parsed → fingerprint hit/miss →
::       Py_Initialize ok → applocal bootstrap ok → python boot ok (GIL released) →
::       ready seen port= → navigate port= → nav completed ok=1

:: 4) API 链路（PC → 设备 loopback 用 forward，方向别搞反）
adb forward tcp:50000 tcp:<ready 里的 port>
:: 写一个新握手码（/auth 用后作废，页面加载后文件已被消费）
adb shell run-as com.pkapp.shell sh -c "printf %s <64位hex> > files/cache/handshake"
:: POST /auth {"handshake":"..."} → token；GET /api/hello + x-myapp-token → 200 JSON
```

## 实测注记（真机踩坑沉淀，Magic6 Pro / MagicOS）

- **后台冻结**：切后台/息屏约 1s 整进程被冻结（FGS 不能免），心跳/线程全部暂停，回前台立即恢复。冻结期间 uptimeMillis 照走——解冻后首个积压 tick（500ms 节拍、冻结期间早已到期）会**先于 onResume 执行**，`now-lastSeqChange`＝整个冻结时长 ≫30s → 误判死出假错误页（★锁屏 >30s 回来必现，单靠 onResume 重置救不了这个竞态★）。壳双重防护：① onResume 重置宽限窗（先到时生效）；② tick 内冻结跳跃检测——相邻拍间隔 >10s 视为进程被冻结过，把跳跃时长从 lastSeqChange/bootStart 中剔除。不掩盖真死：真死时 tick 节拍正常，gap 逐拍爬过 30s，重置后 30s 仍判死。
- **sys.path 两条隐性契约**：① `import applocal` 自身的 import 链（urllib→base64→struct）在 bootstrap 前就需要 `_struct` 等扩展模块 → nativeLibraryDir 必须进 PYTHONPATH（_inject_native 在 bootstrap 内来不及）；② Windows 的 `import app.main` 靠 _pth `import site` 行的 site.getsitepackages() 把 sys.prefix 隐性入 path，Android `Py_NoSiteFlag=1` 无此福利 → runtime 根必须显式在列。
- **资产增量陷阱**：Copy-Item 保留源文件 mtime，构建后拷入的 assets 可能被增量 mergeDebugAssets 漏掉——每次拷 spk 后用 `aapt list ... | findstr assets` 验证在包。
- **adb 语义**：PC→设备端口是 `adb forward`（reverse 方向相反）；mdns 会自动注册一个 `<serial>._adb-tls-connect._tcp` 设备项，手动 connect 后 devices 列表会双条目 → 先 disconnect。
- **同进程 Activity 重建（★二次 boot 崩溃坑★）**：MagicOS 息屏会销毁 Activity 但保留进程（FGS 托底），解锁后同进程重建 Activity → 第二次 `onCreate` → 二次 `engineBoot` 对活解释器再初始化 → libpython SIGSEGV（实测 `PyUnicode_New ← PyRun_SimpleString ← engineBoot`，Magic6 Pro，崩溃后整进程重启）。壳以 companion `runtimeLive` 防重入：活进程重建直接走 re-attach（跳过 engineBoot 与 ready/握手码预清理——那是活心跳的文件），复用既有 uvicorn 重挂 WebView 进轮询，ready seq 连续不归零。验证手法：`wm size` 改分辨率强制同进程重建（与系统销毁重建同一 onCreate 路径）。
- **/auth 码用后作废**：页面加载完成后 handshake 文件被 applocal 消费删除属正确行为；curl 复验需先补写新码。

## 文档映射

| 源码 | 协议章节 |
|---|---|
| `MainActivity.kt` ensureRuntimeExtracted（指纹/流式解压/原子 rename） | §3 步骤 2、§4 四铁律 |
| `MainActivity.kt` env pairs + PYTHONPATH 四条目 | §5.1、§10.2①（★v1.3★） |
| `engine.c` setenv→Py_InitializeEx(0)→PyRun_SimpleString→PyEval_SaveThread | §3 步骤 6–8、§11① |
| `MainActivity.kt` tick 状态机（PH_COLD/PH_RUNTIME/PH_DEAD + onResume 宽限） | §5、§10.2③ |
| `MainActivity.kt` shouldOverrideUrlLoading 握手镜像 | §8（★v1.2★） |
| `MainActivity.kt` 错误页（读 diag 摘要 + 重启/退出） | §9 |
| `BootService.kt` 前台服务（specialUse） | §10.2 引导器存续 |
| `test_shell_contract_device.py` | §12.2（★v1.3★ 实现状态） |
