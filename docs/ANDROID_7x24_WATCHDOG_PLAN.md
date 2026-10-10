# 安卓 7×24 不间断运行方案（Watchdog 守护栈）

> 状态：v1.5 **LOCKED**（v1.4 五轮评审闭环 + v1.5 spike 实测回写。可以进实现）
> v1.4 → v1.5 关键变化（**spike 实测**，工程 spikes/watchdog-spike/，真机 XT2125_4 API 31）：
> ① setAlarmClock **也需要** `SCHEDULE_EXACT_ALARM`——原"免权限"口径被实测证伪（§4.2/§10）；
> ② 新增 §6.6 主线程看门狗线程——僵死进程会吃掉闹钟广播，L2 对"活着但僵死"全盲；
> ③ 开机自启被 OEM 门禁（Moto DeviceGuard）拦截，标准白名单无效（§4.2-4/§7.3/R-10）；
> ④ 三核心假设真机全过：STICKY 重建（进程整死 ~2-12s / TOP 态 killProcess 后 193ms
> 全量复活）、setAlarmClock 进程死亡后仍触发 deviation ≤ 28ms、receiver→startForegroundService
> 中转未被拦
> v1.3 → v1.4 关键变化：WebView 活体探针补上 L0 的"面僵"检测信号（★R1★——healthz 探不到
> WebView 死，无探针则 §3/§6.2 的 WebView 恢复是纸面承诺）；首条闹钟排程归应用启动
> 初始化（★R2★）；setRepeatingAlarmClock 档位修正为 API 21+ 全档可用（★R3★，v1.3 标注有误）；
> 熔断通知预建 NotificationChannel（★R4★）
> v1.2 → v1.3 关键变化：心跳文件加 pending_revive 持久字段钉死"STICKY 重建后谁拉起
> MainActivity"（★P1★，僵死分支复活链的最后一公里）；心跳文件双写者字段所有权 +
> 健康清零评估点归壳内 writer（★P2★）；setAlarmClock 周期 = 触发后重设（★P3★，
> setRepeatingAlarmClock 仅 API 34+ 不作主案）；负例三标注依赖 P0（★P4★）；
> specialUse 的 Play 分发边界提示（★P5★）
> v1.1 → v1.2 关键变化：自杀方式钉死 Process.killProcess（★N1★：am force-stop 自杀会进
> stopped 态反杀 STICKY）；负例一改 kill -9（★N2★：am kill 杀不动前台服务常驻进程）；
> BOOT_COMPLETED 统一经服务中转（★N3★）；熔断复位条件加健康窗口清零 + EXTRA_FROM_WATCHDOG
> （★N4★）；L0 重建补 socket 释放（★N5★）；熔断 on-disk schema（★N6★）；红线2 非失败条款（★N7★）
> v1.0 → v1.1 关键变化：闹钟改 setAlarmClock（API 31+ 节流规避）、revive 统一走前台服务
> 中转（force-stop + 后台启动限制）、新增 boot-loop 熔断（§4.4）、PSS 口径改 smaps_rollup（§6.2）、
> L0 快路径改服务实例重建（§6.1，Py_Initialize 重初始化不采用——官方不支持嵌入式重复初始化）
> 适用范围：pkapp 打包的安卓应用（内嵌 Python + uvicorn/FastAPI 本机服务 + WebView 渲染）
> 参考实测：out/helloApp 于真机 XT2125_4（arm64-v8a，5.5GB RAM）的打包与挂机验证
> 关联文档：docs/BOOTSTRAP_INTEGRITY_PLAN.md（引导面完整性，与本方案正交）

---

## 1. 背景与目标

### 1.1 应用形态与进程模型（★I3 声明★）

pkapp 安卓壳为**单进程形态**：MainActivity、前台服务、LoadLibrary 内嵌的 CPython
解释器与 uvicorn/FastAPI **同属主进程**（dumpsys 实证：仅主进程 + WebView 独立进程）。
UI 由系统 WebView 渲染（sandboxed_process0 独立进程，与主进程隔离）。

此声明是 L1 成立的前提：STICKY 重启拉起前台服务 = 拉起整个主进程 = Python 一并重建。

真机实测启动链路：

```
Py_Initialize → codekey 注入 → applocal bootstrap ok
→ webview ready → ready seen port=37059 seq=1 → nav completed ok=1
```

### 1.2 真机内存基线（挂机 20+ 分钟，**PSS 口径**）

| 进程 | 角色 | 占用 |
|---|---|---|
| 主进程 | Java 壳 + 内嵌 Python + uvicorn/FastAPI | **PSS ~190MB** |
| webview:sandboxed_process0 ×2 | Chromium 渲染器/GPU（独立进程） | 合计 ~50-80MB |
| webview:webview_service | WebView 服务 | RSS ~50MB |
| **合计** | | **~250-300MB** |

（★C4 修正★：§6.2 运行期采样与 §7 验收统一为 PSS 口径，阈值按本基线标定。）

### 1.3 目标

- **7×24 不间断提供本机服务**：healthz 可探活、UI 可交互
- **无人值守自愈**：进程死亡/挂死/断电后，无人工干预恢复
- **有熔断边界**（★C3 新增★）：自愈不能演变为无人知晓的死循环——boot-loop 保护是
  本方案与「盲目重启脚本」的分界线
- **可验收**：有量化红线与负例验证手段

### 1.4 非目标与硬约束（★I1/C1 口径修正★）

- **秒级恢复做不到**。「进程整死 → 复活完成」的最坏空窗 =
  `heartbeat_ttl + 闹钟间隔` ≈ **8min**（180s + 300s）——主案 setAlarmClock
  不受精确闹钟节流限制（正是 v1.1 选它的原因），**所有 API 档位统一此口径**；
  现场若观测到更长空窗，归因 ROM 唤醒抖动/非 GMS 镜像（§9 R-3 盲区），
  不归因闹钟机制（★S1★ 清除 v1.0 setExactAndAllowWhileIdle 时代的 13min 遗留口径）。
  日常自愈走 L0/L1 秒级快路径（§6.1），本口径仅约束灾难态。
- 前台 OOM 的绝对避免（受设备 RAM 上限约束）
- Windows/Linux 平台守护（本方案仅覆盖 Android 壳；桌面端另行评估）
- 被 `am force-stop` 后的自愈（系统级 stopped state 清除全部闹钟与 receiver，
  见 §9 R-5——只能靠部署规范防御）

---

## 2. 现状资产盘点（已实测验证，直接复用）

| 资产 | 现状 | 在本方案中的角色 |
|---|---|---|
| healthz 端点 | 实测 200，返回 `{"ok": true}` | **报活通道本体**：能返回 200 = Python 线程 + uvicorn + 业务全链路通 |
| 壳心跳 Handler 循环 | 已有（`ready seen seq=N` 日志） | 扩展为 healthz 轮询 + PSS 采样的宿主 |
| WebView 渲染器自动重建 | 实测已发生（渲染器被回收后新实例自动拉起） | **OS 级兜底**（★M2 分工★）：渲染器崩溃由 OS 自动重建；L0 仅处理「OS 没兜住」的 WebView 面僵死 |
| 前台服务形态 | 壳已运行于前台服务，与主进程同进程（§1.1） | L1 补强即可 |
| applocal audit.log | 已有 JSONL 审计通道（integrity_purge 已闭环） | watchdog 干预事件记账（§6.4 补轮转），同构复用 |
| Python 内嵌形态 | LoadLibrary 线程，非子进程 | 先天规避 Android 12+ phantom process killer |

---

## 3. 方案总览：四层守护栈

设计原则：**越往下越硬，越不依赖业务进程存活**；**日常自愈在 L0/L1 内闭环，
L2 闹钟只兜灾难态**（★C1 建议三采纳★——外部闹钟频率低是设计使然，不是缺陷）。

| 层 | 名称 | 兜住什么 | 恢复时延 | 盲区 |
|---|---|---|---|---|
| L0 | 进程内自愈 | 服务实例僵死、WebView 面僵、内存爬升 | 秒级 | 解释器本体崩溃/native 崩溃/GIL 死锁 |
| L1 | 系统级保活 | 进程被 LMK 杀后的 STICKY 重启 | 秒~分钟（ROM 相关） | 魔改 ROM 不守约、force-stop |
| **L2** | **进程外兜底** | **进程整死**（唯一不依赖业务进程存活的层） | **ttl + 闹钟 ≈ 8~13min** | Doze 深睡（白名单缓解）、force-stop 断根 |
| L3 | 设备级兜底 | 系统级死机、断电恢复 | 部署规范定 | 成本最高 |

关键认知：**L0/L1 是「活着时少出事、日常故障快恢复」，L2 才是「死了能复活」**。
可靠性由最下层决定；复活速度由最上层决定。

---

## 4. 阶段 1：L2 进程外兜底（核心新增件，~350 行）

### 4.1 组件：WatchdogReceiver + 心跳文件协议

```
壳进程（每 30s）                     watchdog receiver（闹钟触发被系统拉起）
files/heartbeat.json   ←──  读文件判新鲜度
  {ts, pid, healthz_ok}                  ts 距今 > heartbeat_ttl？
        ↑ 活着                           → 否：仅记账，不干预
        ↑ healthz 通                     → 是：查熔断器（§4.4）→ 未熔断则复活
```

### 4.2 实现要点

1. **心跳文件是跨进程判活合同**：receiver 与壳进程无共享内存，以文件新鲜度判死。
   壳每 30s 原子覆写 `files/heartbeat.json`——**写临时文件 + 同目录 rename**
   （★M5 明确★：同 FS 保证原子可见，reader 永不读到半截 JSON）。
2. **闹钟用 `setAlarmClock`**（★C1 主案★）：
   - API 31+ 上 `setExactAndAllowWhileIdle` 受 `SCHEDULE_EXACT_ALARM` 权限门槛
     （Android 14 起新装默认拒绝）与节流限制（最小间隔约 10min），5min 精确恢复
     不成立——**放弃该接口作复活主案**
   - `setAlarmClock` 是唯一不受 Doze/节流限制、可精确触发的接口；代价是状态栏
     闹钟图标（kiosk 场景可接受，评审确认）。**★SPIKE 证伪修订★**：原稿认为
     setAlarmClock 免 `SCHEDULE_EXACT_ALARM`——真机（API 31）未声明该权限时
     setAlarmClock 直接抛 SecurityException。结论：**manifest 必须声明**
     （API 31-32 声明即得；API 33+ 新装默认拒绝，需引导授予"闹钟和提醒"或走
     USE_EXACT_ALARM；spike 复核设置页显示"闹钟和提醒=允许"）。
     setAlarmClock 本身精确度实测极佳：进程死亡/熄屏下连续触发 deviation ≤ 28ms
   - 周期 `alarm_interval`（默认 300s）由 toml 配置。**setAlarmClock 是一次性
     闹钟（★P3★）**：无 interval 参数，WatchdogReceiver 每次触发后必须
     重新 `setAlarmClock(now + alarm_interval)` 形成周期——只 set 一次则
     watchdog 触发一回即停。（`setRepeatingAlarmClock` **自 API 21 即存在，全档位
     可用**（★R3★，v1.3 标注有误）；主案为跨档一致仍统一"触发后重设"。）
   - **首条闹钟排程（★R2★）**：应用启动初始化（MainActivity/WatchdogService
     初始化时）排程第一条 `setAlarmClock(now + alarm_interval)`——不排首条
     则 L2 永远不武装；之后每次触发按上句重设。★SPIKE 佐证★：进程死亡后闹钟由
     AlarmManager 系统侧持有、仍按期触发；每个入口重排是幂等 set，防的是
     "触发广播被僵死进程吃掉后链条断"（§6.6）。
3. **复活路径统一经前台服务中转**（★C2 修正★）：
   ```
   receiver（后台上下文）→ startForegroundService(WatchdogService)
   → 服务内：Process.killProcess(Process.myPid()) 终止自身（若判僵死）
     → 进程属"意外死亡"，STICKY 前台服务由系统重建
     → 重建路径拉起 MainActivity（前台上下文，豁免后台启动限制）
   ```
   - 禁止 receiver 直接 `startActivity`：Android 10+ 后台 Activity 启动限制会静默拦截
   - **自杀方式钉死（★N1★）**：进程内自杀只用 `Process.killProcess(myPid())`
     （或 `System.exit(0)`）——进程为"意外死亡"，STICKY 前台服务由系统重建。
     **绝不使用 `am force-stop` 自杀**：它使应用进入系统级 stopped 态，STICKY
     不重启、闹钟与全部 receiver 失效（= §9 R-5 灾难态，复活链自断）。
     口诀：**杀自己用 killProcess（可复活）；force-stop 是系统级清除（R-5，不可复活）**。
   - **僵死分支收尾——pending_revive 持久标志（★P1★）**：killProcess 后 STICKY
     重启的 service 拿到的 intent 不带任何 extra、内存态全丢——若无持久标志，
     重启后只会空转，MainActivity 永不起（复活链断在最后一公里）。时序：
     ```
     receiver 判死 → 置 heartbeat.json 的 pending_revive = true
     → service 读到 true 且判僵死 → killProcess 自杀
     → STICKY 重建服务（无 extra）→ 读 pending_revive 仍为 true
       → start MainActivity（带 EXTRA_FROM_WATCHDOG）→ 清 pending_revive = false
     ```
     进程整死分支同理：新进程内 service 首轮读到 pending_revive 即拉起。
   - 僵死进程必须先终止再启动（★C2★：`am start` 对僵死进程只是拉起
     已有 Activity，等于没复活）
   - `launchMode="singleTask"` 防 am start 堆叠多个 MainActivity
4. **开机自启**：`BOOT_COMPLETED` receiver → **同样经 WatchdogService 中转**
   （★N3★：Boot receiver 同为后台上下文，直接拉 Activity 会被静默拦截）→
   服务内 start MainActivity（断电恢复场景必配）。
   **★SPIKE 实测红线（XT2125_4 / Moto DeviceGuard）★**：BOOT_COMPLETED 被 OEM
   自启动管理拦截（`BroadcastQueue: Autostart blocked`）；加入 Doze 白名单 +
   `RUN_ANY_IN_BACKGROUND allow` 均无效，应用信息页亦无用户可见自启开关。
   **AlarmManager 闹钟不跨重启** → 自启被拦 = 断电/重启后全部复活链失效。
   部署对策（按优先级）：① 壳应用注册为 HOME/launcher（launcher 自启不受该门禁
   管）；② device-owner/kiosk 供给模式；③ 选型带自启开关或可关 OEM 管控的工控
   设备；④ 部署验收必查 `adb logcat | grep "Autostart blocked"`（§7.3）。
5. **审计闭环**：每次干预写 `audit.log`（复用 `_audit.record_event("watchdog", "revive", {...})`）。

### 4.3 为什么是文件而不是 Binder/广播握手

- 广播在进程死亡时不可达（正是要兜底的场景）
- Binder 需要常驻服务对端，引入新的死亡面
- 文件 + ts 判新鲜：零握手、崩溃安全、可审计

### 4.4 Boot-loop 熔断（★C3 新增——本方案的安全边界★）

**问题**：应用启动即崩（最典型 = P0 完整性 fail-closed，如升级残留清单外文件）时，
`L2 复活 → P0 拒启 → 退出 → L2 再复活` 无限循环：电池榨干、永不恢复、无人告警。

**机制**（熔断器，与心跳同文件持久化，防 receiver 短命内存态）：

**双写者字段所有权（★P2★）**：heartbeat.json 由两个写者更新，**各写各的字段、
禁止全文件覆写**（naive 整文件重写会抹掉对方数据——壳 30s 重写一次就能清空熔断计数）：

| 写者 | 拥有字段 | 频率 |
|---|---|---|
| 壳内心跳 writer | `ts` / `pid` / `healthz_ok` | 每 30s |
| WatchdogReceiver / Service | `circuit_*` / `pending_revive` | 闹钟触发 / 复活时 |

实现约束：读-改-写仅限自有字段集（merge 语义），或两文件分离（heartbeat.json +
circuit.json）；实现期二选一并测试互抹负例。

on-disk schema（★N6★——receiver 每次均为短命进程，窗口判断必须持久化）：
  heartbeat writer：ts, pid, healthz_ok
  receiver/service：circuit_window_start_ts, circuit_count, circuit_open,
                    pending_revive（★P1★ 待复活标志）

熔断窗口 T = 30min（revive_burst_window）
阈值 N = 3 次（revive_burst_limit）
窗口内 revive 计数 ≥ N → 进入熔断态：
  1. 停止自动复活（闹钟仍触发但只记账）
  2. 持久错误态通知（常驻通知「需要人工干预」+ 可选 LED——工控面板可配；
     **通知须预建 NotificationChannel（★R4★，API 26+ 强制，receiver 后台发通知
     无 channel 即静默丢弃）**）
  3. audit.log 记 watchdog_circuit_open 事件（可对接未来上报通道）
复位条件（★N4★ 修正——两级）：
  a) 健康清零：任意一次 revive 后，healthz 连续正常跑满健康窗口
     （healthy_reset_window = 300s）→ 计数清零、窗口起点重置。
     **评估点归壳内心跳 writer（★P2★）**：它 30s 跑一次且天然持有
     healthz_ok 连续性上下文，比 5min 闹钟更及时判定"跑满窗口"并清零。
     防正常抖动累积误熔断（revive#2 成功后健康跑一阵又崩，不应累积到 N）。
  b) 人工清零：用户点击通知/桌面图标。watchdog 经 WatchdogService 启动
     MainActivity 时带 EXTRA_FROM_WATCHDOG=true 显式区分启动来源——
     仅该 extra 缺失（真·人工点击）或 (a) 健康窗口满 → 才清零。
     **执行点（★S3★）**：MainActivity.onCreate 检测 intent 无
     EXTRA_FROM_WATCHDOG → 执行 circuit 计数清零；
     健康清零 (a) 由壳内 writer 经 **merge 语义**写 circuit_count
     （所有权表仍成立——writer 不碰 circuit 其他字段，仅此一处经 merge 写入）。

设计立场：**自愈必须有边界，越界即转为「显式求救」**——否则 watchdog 从资产变负债。
熔断参数进 toml（§8），评审可拍板。

---

## 5. 阶段 2：L1 系统保活（manifest + Activity，~100 行）

前提：前台服务与主进程同进程（§1.1 ★I3★）——STICKY 重启连带 Python 重建。

| 项 | 做法 | 说明 |
|---|---|---|
| 前台服务 | `START_STICKY` + 常驻通知 | 工控场景常驻通知合理 |
| foregroundServiceType | **API 34+：`specialUse`**；< 34 无需声明 type（★M3★） | 注意 Android 15 对 `dataSync` 有 6h 上限——工控常驻场景 targetSdk 34+ 走 `specialUse` 是正解，不回退 dataSync。**分发边界（★P5★）**：specialUse 若经 Google Play 分发需提交用途说明且可能不批——kiosk 工控为侧载分发，不受影响；未来若上 Play 需重新评估 |
| 电池优化白名单 | 启动时 `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` 引导授权一次 | 未授权时 Doze 下闹钟可能延迟；`setAlarmClock` 主案下影响已收窄 |
| 屏幕常亮 | kiosk 页面 `FLAG_KEEP_SCREEN_ON` | 工控面板通常要求常亮 |
| 锁定任务模式 | 可选：`startLockTask()` | 固定 kiosk，防误触退出；兼防 M1 清理器（见 §9） |

定位：L1 是「免费加成」——STICKY 重启延迟不可控且魔改 ROM 可能不守约，
**可靠性兜底永远在 L2**。

---

## 6. 阶段 3：L0 进程内自愈（壳 native 循环扩展，~200 行）

### 6.1 healthz 轮询与分级自愈（★I4 手段修正★）

- 心跳循环扩展：每 30s `GET http://127.0.0.1:<固定端口>/healthz`（§6.3），
  连续 3 次失败 → 按失败形态分级：
  - **超时/服务僵**（解释器存活，uvicorn 实例僵）→ **进程内重建服务实例**：
    新 asyncio loop + 新线程重跑 uvicorn server（秒级）。
    **重建前必须释放旧 socket（★N5★）**：僵 ≠ 退出，旧 uvicorn 往往仍握着
    listen socket，直接重建会 EADDRINUSE → 重建失败退化到 L2，秒级承诺落空。
    顺序：`server.should_exit = True` 触发优雅 shutdown 释放旧 socket
    （不响应则销毁 loop 强制释放）→ bind 时 `SO_REUSEADDR` 兜底。
    **不采用 Py_Finalize → 重 Py_Initialize**：CPython 官方不支持嵌入式场景
    重复初始化（扩展模块/线程状态残留是著名坑），此路不通。
  - **连接拒绝**（解释器本体死：native 崩溃/GIL 死锁/Py_FatalError）→
    停写心跳文件，交 L2 闹钟拉起（进程级问题无进程内解，诚实分层）。
  - **主线程僵死**（★SPIKE 新增★）：healthz 轮询与 §6.3 处置（重建 WebView）
    都跑在主线程上——主线程卡死时**判定可达但处置不可执行**，两分支均失效；
    由独立看门狗线程判死 killProcess，见 §6.6。

### 6.2 PSS 采样分级处置（★C4 口径修正★）

- **指标统一为真实 PSS**：读 `/proc/self/smaps_rollup` 的 `Pss:` 行
  （Linux 4.14+ / Android 9(API 28)+ 内核可用；更低版本回退 `/proc/self/smaps`
  累加 Rss-Pss 项并注明精度损失）。**禁用 VmRSS 作阈值判据**——共享页
  （CPython .so、WebView 共享内存）显著高估，与 §7 验收口径错配。
- 分级阈值按 §1.2 基线（主进程 PSS ~190MB 起步）标定：
  - `pss_webview_rebuild = 400`（MB）：重建 WebView。
    **分工（★M2★）**：渲染器崩溃由 OS 自动重建（已实测）；L0 仅在
    healthz 正常但 WebView 面判定僵死、或 PSS 越线时主动重建。
  - `pss_service_restart = 600`（MB）：主动自杀停写心跳，待 L2 拉起。
- 防抖：连续 2 次采样越线才执行（防瞬时尖峰误杀）。

### 6.3 WebView 活体探针（★R1 新增——"面僵"判定的唯一信号源★）

**缺口**：healthz 是 Python/uvicorn 端点——WebView 渲染进程冻死/卡住时
healthz 仍回 200，L0 的 WebView 重建分支不可达（§3/§6.2 纸面承诺）。必须有
WebView 侧活体信号：

```
WebView 页面 JS（经 JSBridge）每 webview_ping_interval（默认 30s）
→ 向 native 发 ping（seq + ts）
→ 壳监控 ping 连续性：
    连续缺失 > webview_ping_ttl（默认 90s = 3 × interval）
    → 判定"WebView 面僵" → 主动销毁重建 WebView（重载 URL）
```

- **防与 OS 自动重建打架（呼应 ★M2★）**：渲染器被 OS 杀掉重建期间 ping 会短暂
  断流——阈值化（3 周期）天然容忍重建窗口；重建后 ping 恢复即复位计数，
  仅"OS 兜不住的持续断流"才会触发 L0 重建。
- ping 由前端页面 JS 发出，**页面自身冻死则 ping 停**——这正是探针要捕捉的形态；
  壳侧为被动接收，无轮询开销。
- **前置条件（★S2★）**：面僵检测依赖**前端页面实现 JSBridge ping**（探针启用与
  前端资源绑定）。加载不可控第三方/远程页（无 ping 代码）时**不启用该探针**，
  否则永久误判"面僵"→ 每 90s 重建一次 WebView（自残）；此形态仅保留
  §6.2 PSS 越线兜底。kiosk 加载自研打包前端（默认形态）不受影响。
- 配置进 §8：`webview_ping_interval` / `webview_ping_ttl`。

### 6.4 固定端口（★I2 新增★）

- kiosk 构建将 healthz 绑定**固定端口**（toml `healthz_port`，默认 18080——
  §12-3 决议：8080 与现场 web 管理/代理惯用端口冲突面高，改高位），
  动态端口（实测 37059）使 L0 轮询与 §7 adb forward 探活脚本均不确定。
- 端口被占（多实例/其他应用）→ **启动即清晰报错**（diag + 通知），不静默降级回动态。
- 配套：TOML 增加 `healthz_bind = "127.0.0.1"` 默认值。

### 6.5 audit.log 轮转（★I5 新增★）

- 7×24 下 integrity_purge + watchdog_revive + healthz 失败事件持续累加，
  环形轮转：单文件 1MB × 5 份（`audit.log` → `audit.log.1`...），
  实现落 applocal `_audit`，轮转事件本身也记账。

### 6.6 主线程看门狗线程（★SPIKE 新增——僵死自愈的执行器★）

**缺口（spike 实测）**：熄屏下 crash 处理与广播投递时序重叠时，进程进入
"活着但僵死"形态（真机复现：主线程卡 FocusEvent、心跳停止，**L2 闹钟广播投给
僵死进程后 onReceive 永不执行**，60s 后 broadcast ANR 被系统丢弃）——
L2 对僵死态全盲，§6.1/§6.3 的处置也执行不了（都排僵死主线程）。

**设计**：壳进程内一条独立 JVM 线程（daemon，不依赖主线程与 Python）：
主线程 Handler 每 15s 自拍心跳计数 → 看门狗线程每 9s 采样，
连续 3 次无变化（≈27s）→ `Process.killProcess(myPid())` 自杀，交 L1/L2 复活。
参数进 §8 toml（`main_thread_beat_interval` / `watchdog_sample_interval` /
`watchdog_stuck_threshold`）。

**spike 实测（XT2125_4）**：确定性僵死模拟（主线程 sleep 120s）→ 看门狗
30s 内判死 killProcess → 进程死时 Activity 处 TOP 态，AMS 直接
`Start proc for top-activity` **193ms 全量复活**（activity + service 重建，
比 STICKY ~2-12s 更快）；正常心跳下采样至多 stuck=1（15s 心跳 vs 9s 采样），
连续运行 ~15min 零误触。

---

## 7. 烤机验收方案（阶段 4，PC 侧脚本，不进产品）

### 7.1 正例：72 小时长跑

- 每 5min 采样：`dumpsys meminfo`（**PSS，与 §6.2 运行期同口径** ★C4★）、
  healthz 探活（**固定端口** ★I2★）、`pidof` → 落 CSV 画曲线
- **红线 1**：主进程 PSS 日增幅 < 5%（看斜率不看绝对值）
- **红线 2**：healthz 探活失败后恢复时延分级断言：
  - L0/L1 可兜场景（服务僵/进程被杀）→ < 2min
    （★N7 注★：重负载/魔改 ROM 上 STICKY 重建可能超 2min——非 GMS 标准镜像
    属 §9 R-3 已知盲区，超时不算测试失败，记入观察项）
  - 灾难态（进程整死走 L2）→ **< ttl + 闹钟间隔 ≈ 8min**（setAlarmClock 全档位
    精确，无节流档差 ★S1★；超 8min 属 R-3 ROM 抖动盲区，记观察项）

### 7.2 负例一：杀进程复活

```
adb shell kill -9 $(pidof com.example.helloapp)
→ 断言：STICKY/闹钟内复活 + healthz 恢复 200
→ audit.log 出现 revive 事件且与 PC 侧时间戳对拍
```

命令选择依据（★N2★）：
- `am kill` **不可用**——它只杀"安全可杀"（无前台服务/不在前台）的进程，
  本应用前台服务常驻会被直接跳过，负例根本触发不了死亡（测试假绿）；
- `am force-stop` **不可用**——进程进系统级 stopped 态，闹钟/receiver 全失效
  （§9 R-5），测出来的其实是"watchdog 不工作"，属预期行为不是缺陷；
- `kill -9`（SIGKILL）直接杀进程**但不进 stopped 态**——闹钟/receiver 仍注册，
  是验证 L2 复活链的唯一有效复现手段。

### 7.3 负例二：断电恢复

- 直接断电重启设备 → 断言 BOOT_COMPLETED 自启 + healthz 自动恢复 + 零人工干预
- **★SPIKE 前置检查★**：OEM 深度定制 ROM（Moto DeviceGuard 实测拦截）先查
  `adb logcat | grep "Autostart blocked"`——被拦则本负例必红，先落
  §4.2-4 的部署对策（HOME 化 / device-owner / 选型）再测

**目标设备 spike 检查单（★SPIKE 复验，~20min，首次部署/选型评估时执行★）**：
spike（工程 `spikes/watchdog-spike/`，独立 APK 可直接安装）在 XT2125_4（个人手机
API 31）验证的结论分两类——AOSP 平台语义（STICKY 重建、闹钟权限门、FGS 豁免、
僵死吃广播、看门狗线程机制）可泛化；**OEM 行为与时长数值不可泛化**。换目标设备
按下列 4 项复验：

| # | 操作 | 通过判据 | 覆盖章节 |
|---|---|---|---|
| 1 | 安装 spike → 手动启动 → 观察 ≥ 60s | `alarm scheduled` → `ALARM FIRED` 且 deviation 可接受（参考 ≤ 28ms）；无 SecurityException（同时确认设备上"闹钟和提醒"授予状态） | §4.2 / §10 |
| 2 | `adb shell am crash com.pkapp.spike` | 出现新 pid 的 `SERVICE onCreate` + `why=RESTART(null-intent,STICKY 重建)`，记录复活时长量级 | §5 / R-1 |
| 3 | `adb shell am broadcast -a com.pkapp.spike.ZOMBIE -n com.pkapp.spike/.ZombieReceiver` | ~30s 内 `watchdog: main thread STUCK → killProcess` → 新 pid 复活且闹钟链继续 | §6.6 |
| 4 | `adb reboot` → 开机后 `adb logcat -d \| grep "Autostart blocked"` | 无 blocked 且有 `BOOT_COMPLETED received` → 无门禁；被拦 → 落 §4.2-4 对策后再部署 | §4.2-4 / R-10 |

### 7.4 负例三：boot-loop 熔断（★C3 配套新增；依赖 P0 已实装 ★P4★）

> 依赖声明（★P4★）：本负例靠"注入清单外文件触发 P0 fail-closed"构造启动即崩——
> **前提 BOOTSTRAP_INTEGRITY_PLAN 的 P0 已实装**（已随 d3adac7 落地）。P0 缺席时
> 应用不会 fail-closed，本负例无法复现（会假绿），纳入联调顺序在 P0 之后执行。

```
构造启动即崩（注入清单外文件触发 P0 fail-closed）→
断言：观察到 ≤ 3 次自动复活后进入熔断态（不再复活）+
常驻通知出现 + audit.log 有 watchdog_circuit_open →
人工点击通知复位 → 复活恢复且计数清零
```

### 7.5 复活次数的正确解读

- **偶发复活（72h 内两三次）**：watchdog 正常工作的证据
- **频繁复活（每 2h 一次量级）**：系统性问题报警（周期性泄漏/ROM 策略），查根因
- **零复活**：好事（未触发死亡）或坏事（探测空转）——负例 7.2/7.4 必测

---

## 8. 配置设计（集中 pkapp.toml）

```toml
[platforms.android.watcher]
healthz_interval = 30        # 秒；壳内 healthz 轮询周期
healthz_fail_threshold = 3   # 连续失败判死
healthz_port = 18080         # ★I2★ 固定端口（0 = 动态，仅 dev）；§12-3 决议：18080 避开现场惯用 8080
healthz_bind = "127.0.0.1"   # ★I2★ 绑定地址
alarm_interval = 300         # 秒；L2 闹钟周期（setAlarmClock，API31+ 仍精确）
heartbeat_ttl = 180          # 秒；心跳过期阈值（≈ 3 × healthz_interval）
revive_burst_window = 1800   # ★C3★ 秒；熔断窗口 T
revive_burst_limit = 3       # ★C3★ 窗口内 revive ≥ N → 熔断
healthy_reset_window = 300   # ★N4★ 秒；revive 后 healthz 连续正常满此时长 → 熔断计数清零
pss_interval = 300           # 秒；PSS 采样周期
pss_webview_rebuild = 400    # MB；真实 PSS（smaps_rollup 口径，§1.2 基线）★C4★
pss_service_restart = 600    # MB；超限自杀待拉起
webview_ping_interval = 30   # ★R1★ 秒；WebView JSBridge 探针周期
webview_ping_ttl = 90        # ★R1★ 秒；ping 连续缺失超此判定"面僵"（3 × interval）
audit_rotate_size = 1048576  # ★I5★ 字节；audit 轮转单文件上限（×5 份环形）
main_thread_beat_interval = 15   # ★SPIKE★ 秒；主线程自拍心跳周期（§6.6）
watchdog_sample_interval = 9     # ★SPIKE★ 秒；看门狗线程采样周期
watchdog_stuck_threshold = 3     # ★SPIKE★ 连续 N 次无心跳 → killProcess（≈27s）
```

原则：运行参数全部进 toml 单一入口，壳侧只留代码路径不留魔法数。

---

## 9. 边界与风险（诚实声明）

| # | 风险 | 说明 | 缓解 |
|---|---|---|---|
| R-1 | 复活停机下限 = ttl + 闹钟间隔 | **≈ 8min 服务空窗**（setAlarmClock 全档位精确，无 API 档差 ★S1★）；要秒级需 L3 硬件看门狗或双进程互拉，复杂度不成比例 | 日常自愈走 L0/L1 快路径，L2 只兜灾难态 |
| R-2 | Doze 闹钟延迟 | `setAlarmClock` 主案下基本免疫；白名单仍建议授权 | L1 白名单引导 + 部署规范 |
| R-3 | 魔改 ROM | 杀后台策略不可控 | L2 闹钟不受 LMK 影响（内核调度）；部署规范建议标准镜像 |
| R-4 | boot-loop 死循环 | P0 fail-closed × 自动复活 | **§4.4 熔断**：30min/3 次封顶 + 显式求救，负例 7.4 验证 |
| R-5 | **force-stop 断根**（★M1★） | 用户/清理器 `am force-stop` 后：闹钟、全部 receiver（含 BOOT_COMPLETED）失效直至人工启动——watchdog 被彻底废掉，**此为系统级行为，应用层无解** | kiosk 锁定任务模式 + MDM 禁一键清理 + 部署规范明令；文档如实声明失效边界 |
| R-6 | 190MB PSS 起步 | 2GB RAM 低端工控设备偏紧 | 部署规范建议 ≥ 4GB 设备；L0 PSS 自愈兜底 |
| R-7 | WebView 版本老化 | 旧系统 WebView 不更新 | 部署规范：优先 Android ≥ 9（且 ≥ API 28 以获得 smaps_rollup）；前端兼容性覆盖 |
| R-8 | 热/功耗（★M4★） | 常亮 + 前台服务 + WebView 长跑热节流 | 工控通常供电；部署规范：散热间隙、高温告警阈值；可选夜间降频窗口 |
| R-9 | L0 误杀 | 瞬时尖峰触发重建 | 连续 2 次越线防抖 + 阈值可配 |
| R-10 | **OEM 自启动门禁**（★SPIKE 实测★） | 深度定制 ROM（Moto DeviceGuard）拦截 BOOT_COMPLETED；Doze 白名单 + RUN_ANY_IN_BACKGROUND 均无效、无用户开关；闹钟不跨重启 → **重启后复活链全灭** | 部署选型门禁：验收必测 §7.3；对策 HOME 化 / device-owner / 换支持自启的工控设备 |

---

## 10. API 档位与权限矩阵（★I6 新增★）

| 能力 | API < 28 | API 28-30 | API 31-33 | API 34+ |
|---|---|---|---|---|
| smaps_rollup（真实 PSS） | ✗（回退 smaps 累加） | ✓ | ✓ | ✓ |
| setAlarmClock（L2 主案） | ✓ | ✓ | ✓（★SPIKE 证伪修订：也需 SCHEDULE_EXACT_ALARM 声明，实测 API 31 缺权限直接 SecurityException） | 同左 |
| SCHEDULE_EXACT_ALARM | — | — | 声明即得（可被用户撤销） | 新装默认拒绝——引导授予"闹钟和提醒"或 USE_EXACT_ALARM |
| foregroundServiceType | 无需 | 无需 | 无需 | **specialUse**（dataSync 有 6h 上限，勿回退） |
| 后台启动 Activity | 限制弱 | **限制起**（C2：复活必须经前台服务中转） | 同左 | 同左 |
| phantom process killer | 无 | 无 | 12+ 有（内嵌 Python 天然免疫） | 同左 |

**目标档位建议**：targetSdk 34、minSdk 28（工控新机）；API 26-27 旧设备降级运行
（PSS 回退口径 + specialUse 前语义），不支持则部署规范排除。

---

## 11. 实施顺序与工作量

| 阶段 | 内容 | 量级 | 依赖 |
|---|---|---|---|
| 1 | L2：WatchdogReceiver + WatchdogService + 心跳文件 + setAlarmClock + BOOT 自启 + 熔断器 | ~350 行壳工程 | §8 配置 |
| 2 | L1：前台服务补强 + 白名单 + 常亮 + type 档位 | ~100 行 | 可与阶段 1 同 PR |
| 3 | L0：healthz 轮询 + 固定端口 + 服务实例重建 + smaps_rollup PSS 采样 + 分级自愈 | ~200 行 | 依赖阶段 1 心跳文件合同 |
| 4 | 烤机脚本（含负例三熔断验证）| ~250 行 | 依赖阶段 1-3 |

---

## 12. 评审待决问题（v1.5 决议更新——7 条全部拍板）

1. **setAlarmClock 状态栏图标**（C1 主案的唯一代价）——**决议：接受，关闭**。
   kiosk 全屏下状态栏不可见；FGS 常驻通知本就存在，图标为次要视觉噪音；
   无受控替代方案（`setExactAndAllowWhileIdle` 已被 §4.2 否决）。
2. **熔断参数 T=30min / N=3**——**决议：维持 30/3，关闭；72h 烤机后校准**。
   自洽：SLA ≈8min × 3 ≈ 24min < 30min 窗口；30min 内 3 次 = ~10min/次的
   系统性故障率，非偶发抖动。计数口径钉死：**仅 L1/L2 revive 事件累加，
   L0 秒级自愈不计入**（否则 PSS 越线频繁自愈会误熔断；§4.4 实现依此）。
3. **固定端口 8080**——**决议：默认值改 18080（已同步 §6.4/§8），关闭**。
   工控现场 8080 冲突面偏高（设备 web 管理界面/代理/调试器惯用）；高位固定
   同样满足"确定性"。两条不变：bind 失败 fail-fast 不静默降级（§6.4）；
   toml 可改。部署检查单加一条"现场 netstat 核查端口占用"。
4. **PSS 阈值 400/600MB**（smaps_rollup 口径）——**决议：维持，关闭；转部署
   规范执行项**。400/600 ≈ 基线 190MB 的 2.1×/3.2×，适配 ≥4GB 设备（R-6）；
   2GB 本不部署，不为其调参。校准点：目标设备烤机首日实测稳态 PSS，
   按"稳态 ×2 / ×3"复核一次阈值。
5. **锁定任务模式（kiosk 锁定）默认启用**——**决议：kiosk 构建默认启用
   （构建期决定），关闭**。lock task 需 device-owner 供给，而 device-owner
   恰为 R-10 对策②——同一部署流程（配 device-owner → kiosk 锁定 → HOME 化）
   一次解决 R-5 清理器、R-10 自启门禁、导航锁死三件事。开发/调试形态不启用。
6. **L3 设备级（MDM/厂商看门狗）**——**决议：关闭为选型检查单硬性项**
   （采购事实查询，开发侧无阻塞）。目标设备四个必答：
   ① 有无自启门禁（§7.3 spike 检查单 #4，`Autostart blocked` grep）；
   ② 有无 MDM 可用于白名单 + 禁清理器；
   ③ 有无硬件看门狗 / RTC 定时开机；
   ④ 有无 OTA / 省电策略管控。
   有 MDM → 部署规范承接；无 → L0-L2 + HOME 化兜底（spike 已证可用）。
7. **Windows/Linux 桌面端同构守护**——**决议：不另行立项，关闭**。
   桌面端无 Android 的问题集（无 LMK/Doze/后台启动限制，进程前台常驻）：
   内存泄漏 → L0 思路（healthz + PSS 自愈）直接复用；WebView 挂起 →
   任务计划/服务包装为现成方案。L1/L2 同构移植是搬运不需要的复杂度；
   需求出现时按"任务计划重启 + L0 复用"另议，不搬守护栈。
