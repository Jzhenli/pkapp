# pkapp 局域网访问与认证授权方案（★v1.1★）

> 状态：**★v1.1 定稿★（2026-10-02 批准进入 P0 实施）**
> 变更记录：★v1.0★ 初稿评审版 → ★v1.1★ §9 授权层重设计（默认拒绝 + 双集成姿势）、新增 §9.5 FastAPI/领域模型集成、§9.6 应用侧开发约定与边界、§13 补静态豁免集成点、§14 P0 任务修订、新增 §16 POC 验证记录
> 关联文档：[SHELL_PROTOCOL.md](SHELL_PROTOCOL.md) · [pkapp打包方案v8.md](pkapp打包方案v8.md) · [PACKAGER_SPEC.md](PACKAGER_SPEC.md)
> 本文承接多轮方案讨论的收敛结论，供离线评审与后续实现对照。

***

## 1. 背景与动机

当前安全模型：uvicorn 仅绑定 `127.0.0.1`，壳（Windows WebView2 / Android WebView）通过一次性握手码（consume-once）完成本机认证。该模型对"双击即用的个人桌面应用"是正确的，但以下场景全部被挡在门外：

| 场景                       | 现状缺口                        |
| ------------------------ | --------------------------- |
| 局域网内多台 Android 设备，PC 端访问 | 服务锁回环，adb forward 不可运维      |
| Linux 开发板（M3，无壳）部署在机柜    | 无壳 = 无握手机制，远程浏览器是**唯一**交互通道 |
| 工位机 / 展厅 / 产线设备，多人轮换操作   | 本机操作者零认证即用，无身份概念            |
| 应用需要用户权限矩阵（RBAC）         | 现有 /auth 只有"过/不过"一道门        |

**结论**：需要为 pkapp 增加一个应用级身份认证与授权层，同时覆盖本机壳、远程浏览器、程序化访问三类入口，并兼容三平台。

## 2. 目标与非目标

### 目标

- G1 局域网访问：`lan=true` 时服务可被同网段 PC 通过 `ip:port` 直达（浏览器 + 程序）。
- G2 统一认证：本机壳与远程浏览器过同一道登录门，门后（页面、API、权限）完全无差别。
- G3 权限矩阵：应用可定义 角色 → 权限点，路由 → 权限点 的映射，由运行时统一执行。
- G4 无人值守：设备重启后登录态可恢复（工位机/展厅刚需）；机柜程序化访问可全自动换票。
- G5 无键盘部署：开发板烧录上电后，通过浏览器即可完成初始化（创建管理员），无需 ssh 预置。
- G6 零回归：不配置 `[network]` 段的现有应用行为完全不变（双击即用 + 握手免登录）。

### 非目标

- N1 HTTPS/TLS：内网明文 HTTP 可接受（与现有 token 同级）；TLS + 证书管理明确 out of scope，未来作为独立 feature。
- N2 mDNS 自动发现：设备发现靠页面展示 IP / 手输 / 管理系统配置，首版不做 NSD 广播。
- N3 集中式身份源（LDAP/SSO）：P0 不实现，但认证后端留可插拔钩子（见 §8.3）。
- N4 细粒度数据权限（行级/字段级）：授权边界停在 API 路由级，更细的归应用业务代码。

## 3. 设计原则

> **运行时管机制，应用管业务。**

- 登录、会话、Cookie、限速、权限校验执行——这些**机制**由 applocal 统一持有，应用零代码获得。
- 用户存哪、谁是什么角色、权限点叫什么——这些**业务**由应用定义。
- 所有入口过同一道门，门后完全无差别——"统一"体现在门后体验，而非强行统一进门方式。

## 4. 三层架构

```
┌─ 会话层（applocal 持有）─────────────────────────────┐
│  /login 端点 · HttpOnly + SameSite=Strict Cookie     │
│  session 落盘 data_dir（重启可恢复）· 滑动过期        │
│  登录失败限速（5 次锁 1 分钟）· /logout · 全局登出    │
├─ 认证后端（可插拔钩子）───────────────────────────────┤
│  默认实现：data_dir/users.json（PBKDF2 hash + 角色）   │
│  替换钩子：authenticate() 回调 → 未来接 LDAP/SSO      │
├─ 授权层（applocal 持有，rbac/ 子包）─────────────────┤
│  鉴权中间件 · 路由→权限点映射 · 403 结构化错误         │
│  scope["identity"] 贯通到应用处理函数                  │
└──────────────────────────────────────────────────────┘
```

**选文件表而非内置完整用户体系的理由**（决策记录）：工位机/开发板场景几个人用，`users.json` 足够；applocal 是零依赖纯 ASGI 库，塞进完整用户管理 UI 会破坏其定位。将来对接公司统一身份时换认证回调，机制层一行不动。Simple by default, escape hatch when needed.

**rbac 子包边界（★v1.1★）**：授权层实现为 `applocal/rbac/` 独立子包——**只消费 `Identity` 协议（结构化类型），不 import 会话层**，由会话层构造 Identity 传入。代码上随时可整体搬出成独立库；分发上仍随 applocal 进 spk，不付双包管理成本。真拆触发条件（记录，不现在做）：权限功能长出第二个消费场景、膨胀超 ~500 行、或需独立发版节奏。

## 5. 配置设计（pkapp.toml）

```toml
[network]
lan = true                      # 局域网访问总开关（不配置该段 = 个人桌面形态，零回归）
port = 0                        # 0 = OS 自选（默认）；1024–65535 = 固定端口（★v1.2★ 被占 fail-fast）
bind = "0.0.0.0"                # 仅主机地址；固定端口场景配套（防火墙/反代钉端口时用）
auth = "login" | "provision" | "none"   # 默认 "login"；可多选（login+provision 共存）
local_auth = true               # 本机壳是否强制登录；lan=true 时默认 true
session_days = 7                # 会话滑动有效期（默认 7 天）
```

**固定端口语义（★v1.2★）**：`[network].port` 经 manifest `network_port` 透传（签名覆盖），
`MYAPP_PORT` env 可覆盖（env > manifest，与其他 network_* 键一致）；**显式配置端口被占 =
bootstrap fail-fast**（diag.json 记录 + 壳错误页）——固定端口的场景（防火墙/反代/客户端配置
钉死端口）静默漂移比启动失败危害大。`port = 0`（缺省）保持原契约：偏好被占回落 OS 分配、
实际端口以 ready 文件为准。Android 无 env 通道，manifest 是其固定端口唯一入口（壳零改动）。

**默认值语义（点睛设计）**：不配 `[network]` = 个人桌面 = 握手免登录（现状）；配了 `[network]` = 部署形态 = 本机也要认证。"要求本机认证的应用"恰好就是需要局域网/多端访问的应用——语义自然重合。

解析落在 `appspec.load()`（AppSpec 内存对象），经 manifest / `MYAPP_*` 环境变量链透传到壳与 bootstrap。

## 6. 会话层细节

| 项           | 设计                                                                                   |
| ----------- | ------------------------------------------------------------------------------------ |
| 凭证载体        | HttpOnly + SameSite=Strict Cookie（浏览器/壳）；`x-myapp-token` header（程序）                  |
| 存储          | `data_dir/sessions.json`：token hash → identity/过期时间（落盘，重启可恢复）                        |
| 过期          | 滑动 7 天（`session_days` 可配）；`/logout` 单点登出；清 session 文件 = 全局登出                         |
| 限速          | 同源连续 5 次失败锁 1 分钟（防内网爆破；256bit 级凭证不依赖此，人输密码依赖）                                        |
| WebView 持久化 | WebView2/Android WebView 的 Cookie 均持久化在各自 profile → 设备重启后不用重新登录（需 P1 真机验证 Android 侧） |

**会话落盘的取舍（决策记录）**：内存 session 更"安全"（重启即失效），但工位机/展厅设备重启后全体操作员重新登录是运维灾难。落盘 + 有限有效期 + 全局登出能力，安全与便利平衡。

## 7. 认证模型总览（★v1.1 定稿：握手会话化收敛★）

**会话 Token 是唯一凭证，载体两种，领取窗口三个——门内单一路径：**

```
                      ┌─ /login 账号密码（人 + 浏览器/壳 → Cookie）
会话 Token（唯一凭证） ┼─ /auth 握手码（本机壳自动登录；★从旁路降级为领取窗口★）
                      └─ /auth/provision device_key（程序/管理系统 → header）
        ↓ 三窗口产出同一物：会话
门内：resolve session → identity → rbac → 应用（无任何豁免分支）
```

**握手会话化裁定（★v1.1，已批准★）**：
- `POST /auth {handshake}` 验证本机一次性码后 **Set-Cookie 发会话**（响应保留 `{token}` 字段——老页面 JS 照常工作，加法兼容）；
- `local_auth=false`：握手换到的会话使用内置 **local 身份**（个人桌面无需用户表，角色取应用声明的 `local_roles`，缺省全权限）——双击即用体验不变；
- `local_auth=true`：`/auth` 握手入口直接 403，登录页强制——"本机操作者也要认证"约束完好；
- **仅 lan 模式（`[network]` 段存在）启用会话化**：无 `[network]` 段的应用 `/auth` 行为逐位不变（现有 61 测试链不受影响）；
- 门内豁免分支消失、握手会话入 session 表（可审计/可登出）；壳零改动；WebView Cookie 持久化使 7 天内壳重启连握手都省。

API 校验点只有一处：有效会话即放行（Cookie 或 header 任一载体）。

## 8. 认证后端

### 8.1 默认文件实现

`data_dir/users.json`：

```json
{
  "alice": { "pw_hash": "pbkdf2$100000$<salt_hex>$<hash_hex>", "roles": ["operator"], "created": "...", "updated": "..." },
  "svc-monitor": { "pw_hash": "pbkdf2$100000$<salt_hex>$<hash_hex>", "roles": ["viewer"], "type": "service" }
}
```

- 密码 PBKDF2-HMAC-SHA256（stdlib 零依赖，★v1.1 已裁定★，POC 验证 100k 迭代）；**绝不**在 pkapp.toml/manifest 存密码（spk 会被分发，谁拿到包谁知道密码）。
- ★v1.2★ 用户增删查/改密由应用后端实现（admin 权限点保护自己的管理端点）；打包工具不提供用户 CLI。

### 8.2 内置初始账户（G5，★v1.2 裁定★）

打包工具不做用户 CRUD（~~pkapp user CLI~~ 已移除）：lan 门启动时若 `users.json` 无用户，内置创建初始管理员 **admin / 123456**（PBKDF2 落盘，stderr 打一次性提示）。用户改密与用户增删查由应用后端自行实现（用 admin 权限点保护自己的管理端点）。开发板烧录上电 → 浏览器打开 → admin/123456 登录 → 改密使用，全程无 ssh。

> 原方案（v1.0/v1.1）：无用户访问页面 302 `/setup` 先到先建第一个管理员。v1.2 裁定移除首装向导与 `/api/setup/status` 探测端点——默认弱密码换部署零配置；应用若要求强密码，应在自己的首个管理端点上强制改密。

### 8.3 可插拔钩子（为 N3 留门）

应用可注册 `authenticate(username, password) -> identity | None` 替换文件表校验（P0 仅留接口与文档，P2 给出对接外部身份源的示例实现）。

## 9. 授权层与权限矩阵（★v1.1 重设计★）

### 9.1 两层授权分工

```
API 级粗粒度（applocal rbac）：端点能不能调 —— 权限点 + 角色
对象级细粒度（应用领域层）：这条数据你能不能动 —— 领域规则（owner 归属、状态机等）
```

rbac 管不到"这行数据"，领域层不必重复"有没有登录"——各司其职。

### 9.2 应用侧声明（两种姿势，按框架选择）

**姿势 A：FastAPI 依赖注入（POC 验证的主力姿势）**

```python
# app/deps.py —— 一次性适配层（写一次用所有项目）
def require_perm(perm: str):
    def checker(request: Request) -> None:
        if not actor(request).can(perm):
            raise HTTPException(403, detail=f"需要权限 {perm}")
    return Depends(checker)

@router.post("/api/tickets")
async def create_ticket(cmd: CreateTicket, _: None = require_perm("ticket.create")): ...
```

**姿势 B：有序模式表（纯 ASGI 应用）**——v1.0 的静态字典已废弃，评审发现四大缺口
（未命中语义未定义 / 路径参数匹配不了 / 权限点碎片化 / 无动态路由逃生）。修订：

```python
ROUTE_PERMS = [                       # 有序，首个命中生效
    ("/api/public/*",         None),            # 公开（登录免、权限免）
    ("/api/devices/*/status", "device.read"),   # 路径参数通配
    ("/api/devices/*",        "device.manage"), # 前缀批量授权
    (("GET", "/api/hello"),   "hello.read"),    # 精确路由
]
def handler(scope):                    # 命令式逃生（动态路由应用）
    applocal.require(scope, "device.read")
```

### 9.3 可靠性三件套（大端点数应用的关键）

1. **默认拒绝（fail-closed）**：姿势 B 中未命中任何模式行 → 403（带缺失权限点）；姿势 A 中漏配端点落在 router 级兜底依赖上。安全默认，杜绝"漏配即裸奔"。
2. **启动期校验**：模式表格式非法直接启动失败（fail-fast），杜绝静默漂移。
3. **dev 权限覆盖报告**：`pkapp dev` 收集实际命中的 路由→权限来源（声明行 / 命令式 / 拒绝），控制台打印——漏配端点开发期现形，不等到上线被用户 403。

### 9.4 身份贯通与用户管理

- 处理函数内取 `scope["identity"]`（纯 ASGI）/ `request.scope["identity"]`（FastAPI）——POC 实测 v1.0 的 `request.state.identity` 表述有误，纯 ASGI 无 Starlette 上下文。
- **用户管理 UI 不内置**：应用用 `admin` 权限点保护自己的管理页面（应用本来就要做业务管理界面），applocal 只提供 `pkapp user` CLI 兜底。

### 9.5 FastAPI + 领域模型（DDD）集成（★v1.1 新增，POC 验证★）

FastAPI app 本身就是 ASGI 可调用，直接挂在 applocal 链后——applocal 保持零依赖（不 import FastAPI），FastAPI/pydantic 是应用依赖进 spk 的 site-packages。

```
请求 → applocal 链（会话 → rbac 中间件） → FastAPI 路由 → 领域服务 → 聚合
         认证 + API 级粗粒度权限            （对象级细粒度授权在这里）
```

- **身份桥接**：领域层定义 `Actor.from_identity(request.scope["identity"])`，领域服务以 Actor 做对象级判断（如"仅工单 owner 或 admin 可关闭"）——rbac 管端点，领域管数据。
- **领域异常映射**：`DomainError` 统一走 `@fa.exception_handler`（403/404/409）——**不要**写 `*args/**kwargs` 签名的包装装饰器，FastAPI 会把 args/kwargs 解析成 query 参数（POC 实测 422）。
- **打包**：fastapi/pydantic 写进 `pkapp.toml` `[dependencies]`；pydantic v2 的 pydantic-core 有各平台 wheel，Android/Linux 打包按平台抓取即可。

### 9.6 应用侧开发约定与边界（★v1.1 新增★）

原则：**方案是"替代自研"而非"额外加码"**——多用户应用本来就要写登录/会话/密码存储/权限检查，方案把这些拿走，应用只留声明。日常开发体验不变（FastAPI/pydantic/领域模型照常，applocal 不 import 应用框架，框架版本升级自由；不配 `[network]` 段的应用零约束）。

**三个约定**：

| # | 约定 | 说明 |
| --- | --- | --- |
| 1 | 逐端点声明权限 | `require_perm("xxx")` 挂为依赖参数。这不是本方案发明的成本——任何 RBAC 都必须回答"这个端点要什么权限"；漏配有 dev 覆盖报告兜底 |
| 2 | 取身份走 `scope["identity"]` | 一行 `Actor.from_identity()` 桥接进领域层 |
| 3 | API 路径用 `/api/*` 前缀 | 会话门靠它区分"页面 302 登录 / API 401 JSON"分流——唯一的路径命名约束 |

**三个边界**：

| # | 边界 | 说明 |
| --- | --- | --- |
| 1 | 认证态统一归 applocal | 不可再用 FastAPI `OAuth2PasswordBearer` 等自建 token 体系（会与会话门打架）。从零开发无感；已有自研 auth 的老应用迁移需改造一次 |
| 2 | 静态文件归 applocal 静态豁免 | 应用不要再挂 `StaticFiles` 等同类路由（P0 调整链序后此边界更清晰） |
| 3 | 特殊认证需求走逃生通道 | 机器对接 → provision 档（§11）；外部身份源（LDAP/SSO/第三方）→ 认证回调钩子替换文件表（§8.3），机制层不动 |

## 10. 入口行为全景（最终版）

| 入口                     | local\_auth=false（个人桌面）                | local\_auth=true（部署形态）                   |
| ---------------------- | -------------------------------------- | ---------------------------------------- |
| 壳 WebView（Win/Android） | 握手免登录（**现有机制原样保留**）                    | 显示登录页 → Cookie 留在 WebView profile → 重启不丢 |
| 远程浏览器                  | —                                      | 登录页 → Cookie                             |
| 管理系统/程序                | provision 换设备服务 token（权限独立可配，P0 默认全权限） | 同左                                       |
| `auth="none"`（显式）      | 受控网段裸奔，零摩擦                             | 同左                                       |

**为什么本机壳入口不默认改成登录**（决策记录）：壳握手与账号密码回答的是两个不同问题——握手证明**位置**（本机），登录认证**身份**。强制统一会让双击即用的桌面应用被迫初始化密码、忘密码找回；无人值守设备重启后卡在登录页。成熟产品均入口分治（Chrome DevTools 本机直连/远程 token；Jupyter 本机自动带 token/远程密码）。`local_auth=true` 是显式 opt-in，不是默认。

## 11. 程序化访问（provision，机柜场景）

```
部署时（一次性，★v1.2★ 零触摸）：lan 门启动发现 data_dir/lan.key 缺失即自动生成
                  256bit 随机密钥（原子写），控制台/日志一次性展示
                  → 管理系统从设备侧读取该输出登记（~~pkapp provision-key CLI~~ 已移除）

运行时（每次重启后，全自动）：
  PC → POST /auth/provision {"device_key": "<key>"} → {"token": "<会话 token>"}
  之后 API 带 x-myapp-token 直连
```

- 两把钥匙分离：`device_key` = 设备身份（长期、部署时注入）；`token` = 会话凭证（重启轮换，撤销语义完整保留）。重启即作废旧票，管理系统用 device\_key 自动重取，全程无人工。
- `/auth/provision` 密钥错误一律 401，不区分"不存在/不匹配"；256bit 高熵，内网爆破不现实。

## 12. 平台落地差异

| <br /> | Windows（有壳）                       | Android（有壳）                                                                          | Linux 开发板（无壳，M3）          |
| ------ | --------------------------------- | ------------------------------------------------------------------------------------ | ------------------------- |
| 绑定     | 默认 127.0.0.1；`lan=true` → 0.0.0.0 | 同左                                                                                   | 无壳模式 `lan` 恒真，默认 0.0.0.0  |
| 明文限制   | 无                                 | **network\_security\_config 是打包期固定的** → apk.py 按 `[network]` 开关注入 config 变体（放行局域网明文） | 无                         |
| 连接信息暴露 | 不需要（本机壳）                          | 应用页面内展示 `location.host`（IP 自带）                                                       | 启动日志 + token 文件（ssh/串口可读） |
| 透传     | 壳 env 列表加 `MYAPP_BIND` 等透传        | JNI setenv 同链                                                                        | systemd/启动脚本设 env 即通      |

env 透传（`MYAPP_BIND` / `MYAPP_*`）是三平台统一底座——Linux 端随 M3 落地几乎零额外成本。

## 13. 安全分析（威胁模型）

| 威胁             | 缓解                                                                                         |
| -------------- | ------------------------------------------------------------------------------------------ |
| 局域网内任意主机扫到服务   | 默认关；`lan=true` 显式开启 + 必经认证（`none` 档除外且为显式选择）                                               |
| 密码爆破           | 限速锁定（§6）；密码不进 spk/manifest                                                                 |
| device\_key 爆破 | 256bit 高熵；错误一律 401 无区分                                                                     |
| token 泄露       | 有限有效期 + 重启轮换 + 全局登出（清 sessions.json）                                                       |
| CSRF           | SameSite=Strict + HttpOnly                                                                 |
| 会话固定           | 登录成功重发新 token                                                                              |
| 明文传输被嗅探        | 内网明文可接受（N1 明确 out of scope）；provision 的 device\_key 会出现在 POST body —— 内网威胁模型下可接受，TLS 为终极解法 |
| 静态豁免截胡认证门（★v1.1 新增★） | applocal `build_asgi_app` 现链序 = 静态豁免（GET dist 文件 + SPA 兜底）→ token → 用户 app：浏览器导航 `GET /login`、`GET /setup` 被上游返回演示页，认证门收不到。**P0 必须调整链序**（见 §14） |

## 14. 实施计划

### P0（本计划实施范围）

| 模块                  | 内容                                                                       | 规模      |
| ------------------- | ------------------------------------------------------------------------ | ------- |
| `applocal` 链序调整（★v1.1 新增★） | lan/local\_auth 模式下静态服务挪到会话门**之后**（或豁免面收窄至仅登录/首装页）——POC 发现的关键集成点 | \~40 行 |
| `applocal/rbac/` 子包 | 会话层（session.py：login/logout/Cookie/落盘/限速）+ 授权中间件 + `/setup` 首装 + `/auth/provision`；rbac 只消费 Identity 协议 | \~540 行 |
| 认证后端                | `users.json` 读写 + **PBKDF2**（POC 已验证，100k 迭代）+ 认证回调钩子接口                   | \~120 行 |
| `pkapp user` CLI    | add/list/remove/passwd                                                   | \~80 行  |
| pkapp 配置链           | `[network]` 段解析（appspec）+ manifest/env 透传 + `provision-key` 命令           | \~100 行 |
| shell-windows       | env 列表加 `MYAPP_BIND` 等透传（**登录页是网页，壳零逻辑改动**；握手协议不动）                       | \~10 行  |
| 测试                  | 认证层安全件从宽：会话/权限/限速/首装/provision 单测 + Windows 真机 e2e（对照 POC 验证清单 §16）       | \~300 行 |

**合计核心 \~850 行 + 测试 \~300 行。**（POC 原型 out/hi-chain/HiApp `app/auth_gate.py` \~400 行为迁移蓝本）

已随 POC 顺修的主线 bug：`dev.py build_dev_env` 传相对 `MYAPP_DATA_DIR` 触发 `_env._abs` ContractError——`project_dir` 已补 `os.path.abspath`。

> **★P0 已实施（2026-10-02）★**：session.py / rbac/ / _gate.py 门链（静态门后）/
> appspec `[network]` + manifest `network_*` 透传（壳零改动裁定，env 列表不加键）/
> 内置初始 admin/123456 + provision 零触摸建钥（★v1.2 裁定：~~pkapp user~~ /
> ~~provision-key~~ 两个 CLI 已移除，打包工具不做用户管理）/
> dev 权限覆盖报告（MYAPP_DEV=1 → stderr `[auth-coverage]`）/
> 认证层单测 applocal/tests/test_auth.py（39 项）。
> 偏离表一行：shell-windows "env 列表加 MYAPP_BIND" 不需要——manifest 主通道 +
> MYAPP_* env 运维覆盖层已覆盖（§12），壳 C 解析器忽略未知键，三平台零改动。
> 实施补强：SessionStore 滑动续期落盘节流 60s（重启丢失窗口 ≤60s，避免每请求写盘）；
> ④ 号豁免码值校验（review F1 修复：`?handshake=` 必须与握手文件比对一致才放行，
> 封死"键存在即豁免"的永久旁路，文件只读不消费）；UserStore.verify 耗时均衡
> （review F3 修复：缺失用户跑等价 PBKDF2，用户名存在性不经时序外泄）；
> UserStore mtime 变更重读（架构方案A：应用后端运行中建/改/删用户，门 verify/exists
> 前 stat 检测免重启可见——权威数据回到文件，v1.2 裁定自此无悬空缺口）；
> 登录 UI 归属定稿（架构模糊带关闭）：ui/login.html 存在则门在 GET /login
> 原样回该文件（Vue 自包含编译产物，no-store），内置页退化为零前端兜底——
> UI 归应用、机制归门，豁免面恒等于一条路由（§8.3）；
> token 载体收敛（真机联调前定稿）：/auth 响应体不再含 token（`{"ok": true}`），
> 浏览器唯一载体 = HttpOnly Cookie；x-myapp-token 保留为机器客户端载体，
> 其 token 仅由 /auth/provision 签发——"header 仅机器客户端"自此字面成立。

### P1

Android `network_security_config` 打包期注入 + Magic6 Pro 真机验证（壳 WebView 登录态持久化 + 局域网访问全链）。

### P2（随 M3）

Linux 无壳接入 + 认证回调示例（对接外部身份系统）。

## 15. 开放问题（★v1.1 状态更新★）

1. ~~**bcrypt 依赖**~~ → **已裁定（POC 验证）**：纯 Python PBKDF2-HMAC-SHA256（100k 迭代 + 随机盐），零依赖，POC 全链可用。
2. ~~**ROLES/ROUTE_PERMS 暴露方式**~~ → **已裁定（POC 验证）**：FastAPI 场景走依赖注入（姿势 A），纯 ASGI 场景走 module 级模式表（姿势 B），见 §9.2。
3. **provision token 的权限**：P0 默认全权限（管理系统 = 受信基础设施）vs 强制映射到可配角色。——待终审（P0 按前者实现，`provision_roles` 预留配置位）。
4. ~~**`/setup` 首装窗口**~~ → **已裁定（★v1.2★）**：移除首装向导——门内置初始 admin/123456，改密与用户管理归应用后端（§8.2）；打包工具不提供用户 CRUD CLI。
5. **session\_days 上限**：要不要硬上限（如 30 天）防误配成"永不过期"。——待终审（P0 不设硬上限，文档告警）。
6. **文档落点**：本方案实现后并入 SHELL\_PROTOCOL.md 还是独立成 AUTH\_PROTOCOL.md。——待终审（P0 期间本文件为权威）。

7. ~~**握手旁路 vs 单一登录门**~~ → **已裁定（2026-10-02，批准实施）**：握手降级为领取窗口（会话化），收敛为门内单一路径，详见 §7。文档状态升 **v1.1 定稿**，进入 P0 实施；#3–#5 按 P0 默认值实现（均已注明预留配置位），#6 实现后随验收定。

> **文档状态：★v1.2★（2026-10-02 P0 实施完成 + 内置账户裁定；v1.1 定稿批准 P0）**

## 16. POC 验证记录（★v1.1 新增，2026-10-01）

实验载体：`out/hi-chain/HiApp`（FastAPI 0.142.2 + 领域模型 Device/Ticket + auth\_gate 原型 ~400 行，应用侧隔离实现，不动 applocal 主线）。

### 16.1 验证结论（curl 16 项 + 浏览器 UI 9 步全通过）

| 验证项 | 结果 |
| --- | --- |
| 首装流程（status 探测 → setup 建管理员 → 二次 setup 拒绝 404） | ✅ |
| 三角色登录 302 / 错密码 401 / 无 cookie 401 / 登出后 401 | ✅ |
| 限速（错 5 次 → 第 6 次 429 锁定 60s） | ✅ |
| API 权限矩阵（viewer 读 200 / reboot 403 / admin 403；operator 放行；admin users 200） | ✅ |
| 对象级授权：operator 关 admin 工单 → 领域拒 403 "only owner or admin"；admin 关 operator 工单 → 200；关已关闭 → 409 | ✅ |
| 审计日志 / 会话落盘（dev 重启登录态保留） | ✅ |
| 浏览器 UI：登录卡 → 身份卡 → 端点试探矩阵（200 绿 / 403 红）→ 登出 | ✅ |
| 应用侧接入成本 | ROLES 表 ~6 行 + 每端点 `require_perm(...)` + 组装 1 行；领域模型照常写 |

### 16.2 POC 发现（已反哺本方案）

1. **主线 bug（已修）**：`dev.py build_dev_env` 传相对 `MYAPP_DATA_DIR` → `_env._abs` ContractError；`project_dir` 补 `os.path.abspath`。
2. **FastAPI 集成正道**：领域异常走 `@fa.exception_handler`；`*args/**kwargs` 包装装饰器会被 FastAPI 当 query 参数（422）。
3. **P0 关键集成点**：applocal 静态豁免在认证门上游，SPA 兜底截走 `GET /login`、`GET /setup`（§13 末行 / §14 首行）；POC 用 `/api/setup/status` 探测 + 页面内渲染表单绕过。
4. **领域层规则与 API 门的分工实证**：operator 对离线设备 reboot——API 门放行（有 device.control），领域层按"离线设备不可重启"拒绝——两层授权各司其职的直接证据。
