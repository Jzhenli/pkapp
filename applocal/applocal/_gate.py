"""applocal._gate —— lan 模式认证门（NETWORK_AUTH_DESIGN.md ★v1.2★ §7/§10/§14）。

门内单一路径（§7）：三入口产出唯一会话 token——
  /login 账号密码（人）· /auth 握手码（本机壳，会话化）· /auth/provision device_key（程序）
→ resolve → scope["identity"] → 静态（门后）→ rbac → 用户应用。

用户管理裁定（★v1.2★）：打包工具不做用户 CRUD——门启动时内置初始管理员
admin/123456（仅 login 模式），改密与用户管理由应用后端自行实现（admin 权限点保护）。

链序关键点（§13/§14/§16.2#3 的 P0 集成点）：
  1. 固定端点（登录/壳协议）在会话检查之前——否则被自己的门拦死；
  2. ?handshake= 查询窄豁免：壳首次导航时页面必须先加载，JS 才能换会话；
  3. 静态服务挪到会话门之后——/login 不再被上游 SPA 兜底截走（POC 实证缺陷）。

机制层（本文件）与应用业务（角色表/权限点/路由表）分离：ROLES / ROUTE_PERMS 由应用
入口模块声明，bootstrap 拾取后传入（§9.2 姿势 B；FastAPI 姿势 A 可不声明 route_perms）。
"""
from __future__ import annotations

import hmac
import json
import os
import secrets
import sys
import urllib.parse

from . import rbac
from ._core import (_AUTH_BODY_MAX, _MIME, _header, _json, _read_static,
                    _resolve_static, _respond, _wants_html)
from .session import (RateLimiter, SessionStore, UserStore, cookie_clear_header,
                      cookie_header, cookie_token)

PROVISION_KEY_FILE = "lan.key"     # §11：device_key 落 data_dir/lan.key（256bit，密钥禁入 manifest）
ADMIN_USER = "admin"               # ★v1.2★ 内置初始管理员（§8.2：默认密码登录后自行修改）
DEFAULT_ADMIN_PASSWORD = "123456"

# 内置兜底登录页（★v1.2★ UI 归 dist：dist/login.html 存在时本页不使用）
_LOGIN_PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>登录</title>
<style>body{{font-family:system-ui;display:flex;min-height:100vh;align-items:center;
justify-content:center;background:#f3f4f6}}form{{background:#fff;padding:2rem;border-radius:8px;
box-shadow:0 1px 4px rgba(0,0,0,.1);width:260px}}input{{width:100%;padding:.5rem;margin:.4rem 0;
box-sizing:border-box;border:1px solid #d1d5db;border-radius:4px}}button{{width:100%;padding:.5rem;
background:#2563eb;color:#fff;border:0;border-radius:4px;cursor:pointer}}p{{color:#dc2626;font-size:.85rem}}</style>
</head><body><form method="post" action="/login"><h3>登录</h3>
{err}<input name="user" placeholder="用户名" required autofocus>
<input name="password" type="password" placeholder="密码" required>
<button>登录</button></form></body></html>"""


# ── ASGI 基元 ───────────────────────────────────────────────────────────
async def _read_body(receive, limit: int = _AUTH_BODY_MAX) -> bytes | None:
    """读全请求体；超限返回 None（413）。loopback/lan 也防异常大 body 吃内存。"""
    body = b""
    while True:
        m = await receive()
        body += m.get("body", b"")
        if len(body) > limit:
            return None
        if not m.get("more_body"):
            return body


def _form(body: bytes) -> dict:
    out = {}
    for kv in body.decode("utf-8", "replace").split("&"):
        k, _, v = kv.partition("=")
        out[urllib.parse.unquote_plus(k)] = urllib.parse.unquote_plus(v)
    return out


def _client_ip(scope) -> str:
    client = scope.get("client")
    return client[0] if client else "?"


async def _page(send, html_text: str, status: int = 200) -> None:
    await _respond(send, status, "text/html; charset=utf-8", html_text.encode("utf-8"))


async def _redirect(send, location: str, cookie: str | None = None) -> None:
    extra = [(b"location", location.encode("latin-1"))]
    if cookie:
        extra.append((b"set-cookie", cookie.encode("latin-1")))
    await _respond(send, 302, "text/html; charset=utf-8", b"", extra=extra)


def _handshake_ok(scope, handshake_file: str) -> bool:
    """④ 号豁免的守门条件：查询串 ?handshake=CODE 与握手文件当前码一致（★v1.2 修复★）。

    只查"键存在"会成为永久旁路——任意请求带 ?handshake=1 即可匿名过会话门
    （拉静态资源/以 identity=None 入应用）。此处只读比对、不消费文件
    （消费仅发生在 POST /auth，壳 NavigationStarting 会在每次导航时重写）。
    """
    code = ""
    for p in (scope.get("query_string") or b"").split(b"&"):
        k, _, v = p.partition(b"=")
        if k == b"handshake":
            code = v.decode("utf-8", "replace")
            break
    if not code or not handshake_file:
        return False
    try:
        with open(handshake_file, encoding="utf-8") as f:
            current = f.read().strip()
    except OSError:
        return False
    return bool(current) and hmac.compare_digest(code.encode("utf-8"),
                                                 current.encode("utf-8"))


def _provision_key(data_dir: str) -> str:
    """读 data_dir/lan.key；缺失 = provision 禁用。请求时读取（重启补建后无需重装）。"""
    try:
        with open(os.path.join(data_dir, PROVISION_KEY_FILE), encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""


def _atomic_text(path: str, text: str) -> None:
    tmp = f"{path}.tmp{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)                # 原子写（项目铁律，同 users/sessions.json）


# ── 门组装 ──────────────────────────────────────────────────────────────
class _DevCoverage:
    """§9.3 dev 权限覆盖报告：MYAPP_DEV=1 时收集 rbac 判定打印 stderr。

    同 (method, path, source) 只印首现（控制台不刷屏）；判定变化（如 deny→放行）
    会换 source 再印——漏配端点开发期现形，不等到上线被用户 403。
    """

    def __init__(self) -> None:
        self._seen: set = set()

    def __call__(self, event: dict) -> None:
        key = (event.get("method"), event.get("path"), event.get("source"))
        if key in self._seen:
            return
        self._seen.add(key)
        mark = {"unrouted": "未路由 → 403（fail-closed，须补 ROUTE_PERMS 或 (pattern, None) 行）",
                "deny": "权限不足 → 403"}.get(event.get("source"), event.get("source"))
        print(f"[auth-coverage] {event.get('method')} {event.get('path')} "
              f"perm={event.get('perm')} ({mark})", file=sys.stderr, flush=True)


def build_lan_app(user_app, cfg, *, roles_table=None, route_perms=None):
    """lan 模式 ASGI 组装：/healthz → 会话门 → 静态（门后）→ rbac → 用户应用（§14）。"""
    net = cfg.network
    table = roles_table or {}
    ttl = net.session_days * 86400
    os.makedirs(cfg.paths.data_dir, exist_ok=True)   # users/sessions 落盘自愈（同 write_ready 姿势）
    users = UserStore(cfg.paths.data_dir)
    sessions = SessionStore(cfg.paths.data_dir, ttl_s=ttl)
    limiter = RateLimiter()
    report = _DevCoverage() if cfg.runtime.dev else None   # §9.3：dev 权限覆盖报告
    want_login = "login" in net.auth            # §5：默认 "login"；provision 显式多选
    want_provision = "provision" in net.auth
    require_session = "none" not in net.auth    # auth="none"（§10）：受控网段裸奔
    custom_login = os.path.join(cfg.paths.static_dir, "login.html")  # ★v1.2★ UI 归 dist

    if want_login and not users.exists():
        # ★v1.2★ §8.2 裁定：内置初始管理员（打包工具不做用户 CRUD，改密/用户管理归应用后端）
        users.create(ADMIN_USER, DEFAULT_ADMIN_PASSWORD, ["admin"])
        print(f"[applocal] 已创建初始管理员 {ADMIN_USER}（默认密码 {DEFAULT_ADMIN_PASSWORD}），"
              f"请登录后立即修改", file=sys.stderr, flush=True)
    if want_provision and not _provision_key(cfg.paths.data_dir):
        # §11：device_key 零触摸生成（仅在缺文件时补建——要禁用 provision 请从 auth 模式移除）；
        # 打到控制台/日志即分发通道：管理系统从设备侧读取一次后登记
        key = secrets.token_hex(32)
        _atomic_text(os.path.join(cfg.paths.data_dir, PROVISION_KEY_FILE), key + "\n")
        print(f"[applocal] device_key 已生成（{os.path.join(cfg.paths.data_dir, PROVISION_KEY_FILE)}，"
              f"仅此一次展示）:\n{key}", file=sys.stderr, flush=True)

    def _perms(roles) -> list:
        # 内置约定：admin 角色与 "*" = 全权限——应用 ROLES 表未定义 admin 时管理员也不锁死
        if "*" in roles or "admin" in roles:
            return ["*"]
        return rbac.roles_to_perms(roles, table)

    def _identity(user: str, roles) -> dict:
        return {"user": user, "roles": list(roles), "perms": _perms(roles)}

    core = (rbac.rbac_gate(user_app, route_perms, dev_report=report)
            if route_perms else user_app)      # 模式表组装一次（§9.2 姿势 B）

    async def inner(scope, receive, send):
        if report is not None:
            scope["dev_report"] = report       # §9.3：require() 命令式判定也进覆盖报告
        # 门后链：静态（GET/HEAD + SPA 兜底）→ rbac（声明了模式表才启用）→ 用户应用
        if scope["type"] == "http" and scope["method"] in ("GET", "HEAD"):
            static = cfg.paths.static_dir
            hit = _resolve_static(static, scope["path"])
            if hit is None and _wants_html(scope):
                hit = os.path.join(static, "index.html")     # SPA 路由兜底
            if hit and os.path.isfile(hit):
                body = _read_static(hit)
                if body is not None:
                    ext = os.path.splitext(hit)[1].lower()
                    extra = [(b"cache-control", b"no-store")] if ext in (".html", ".htm") else ()
                    return await _respond(send, 200, _MIME.get(ext, "application/octet-stream"),
                                          body, extra, head=(scope["method"] == "HEAD"))
        return await core(scope, receive, send)

    async def gate(scope, receive, send):
        method, path = scope["method"], scope["path"]

        # ── 1) 壳协议 /auth：握手码 → 会话（§7 会话化；local_auth=true → 403 强制登录）──
        if path == "/auth" and method == "POST":
            if net.local_auth or not cfg.paths.handshake_file:
                return await _json(send, 403, {"error": "login required"})
            try:
                body = await _read_body(receive)
                if body is None:
                    return await _json(send, 413, {"error": "payload too large"})
                code = json.loads(body or b"{}").get("handshake", "")
                if not isinstance(code, str):
                    return await _json(send, 403, {"error": "bad request"})
            except (ValueError, OSError):
                return await _json(send, 403, {"error": "bad request"})
            try:
                with open(cfg.paths.handshake_file, encoding="utf-8") as f:
                    current = f.read().strip()
            except OSError:
                current = ""
            if not current or not code or not hmac.compare_digest(
                    code.encode("utf-8"), current.encode("utf-8")):
                return await _json(send, 403, {"error": "invalid handshake"})
            try:
                os.remove(cfg.paths.handshake_file)      # 用后作废；壳每次导航重写
            except OSError:
                pass
            ident = _identity("local", net.local_roles)  # §7：内置 local 身份（无需用户表）
            token = sessions.create("local", ident["roles"], ident["perms"])
            return await _respond(send, 200, "application/json",
                                  b'{"ok": true}',    # ★收敛★：浏览器唯一载体=Cookie；token 仅 provision 签发
                                  extra=[(b"set-cookie",
                                          cookie_header(token, ttl).encode("latin-1"))])

        # ── 2) provision（§11 机柜程序化访问）────────────────────────────────
        if path == "/auth/provision" and method == "POST":
            if not want_provision:
                return await _json(send, 404, {"error": "not found"})
            body = await _read_body(receive)
            if body is None:
                return await _json(send, 413, {"error": "payload too large"})
            try:
                key = json.loads(body or b"{}").get("device_key", "")
            except ValueError:
                key = None
            current = _provision_key(cfg.paths.data_dir)
            if (not current or not isinstance(key, str) or not key
                    or not hmac.compare_digest(key, current)):
                return await _json(send, 401, {"error": "unauthorized"})  # §11：无区分 401
            ident = _identity("provision", net.provision_roles)
            token = sessions.create("provision", ident["roles"], ident["perms"])
            return await _json(send, 200, {"token": token})

        # ── 3) 登录端点（§8.2；auth 模式含 login 才存在）──────────────────
        if want_login:
            if path == "/login" and method == "GET":
                try:    # dist/login.html（Vue 自包含登录页）优先；缺失落内置兜底页（纯后端可用）
                    with open(custom_login, "rb") as f:
                        data = f.read()
                except FileNotFoundError:
                    return await _page(send, _LOGIN_PAGE.format(err=""))
                return await _respond(send, 200, "text/html; charset=utf-8", data,
                                      extra=[(b"cache-control", b"no-store")])
            if path == "/login" and method == "POST":
                ip = _client_ip(scope)
                if limiter.locked(ip):
                    return await _respond(send, 429, "text/plain; charset=utf-8",
                                          "尝试次数过多，请稍后再试".encode("utf-8"))
                body = await _read_body(receive)
                if body is None:
                    return await _json(send, 413, {"error": "payload too large"})
                form = _form(body)
                rec = users.verify(form.get("user", ""), form.get("password", ""))
                if rec is None:
                    limiter.fail(ip)                          # §6：5 次失败锁 60s
                    return await _page(send,
                                       _LOGIN_PAGE.format(err="<p>用户名或密码错误</p>"), 401)
                limiter.reset(ip)
                ident = _identity(form.get("user", ""), rec.get("roles", []))
                token = sessions.create(ident["user"], ident["roles"], ident["perms"])
                return await _redirect(send, "/", cookie=cookie_header(token, ttl))
            if path == "/logout" and method == "POST":
                sessions.drop(cookie_token(scope))
                return await _redirect(send, "/login", cookie=cookie_clear_header())

        # ── 4) 壳首次导航窄豁免（§14）：?handshake= 且码值与握手文件一致 → 放页面加载。
        #    码不符静默落入 ⑤/⑥ 正常链（会话或登录门）——F5 后旧码随文件已消费而失效，
        #    由 Cookie/sessionStorage 会话兜底，不依赖此豁免。
        #    ★login 模式不豁免★：豁免只放行带码的文档请求，SPA 的 /assets/* 子资源
        #    无码无会话仍被 ⑥ 截走 → 首屏半加载白屏、且到不了登录页。login 模式下
        #    未持会话的首航应整体 302 /login（登录页自包含，不受影响）。
        if not (require_session and want_login) and _handshake_ok(
                scope, cfg.paths.handshake_file):
            return await inner(scope, receive, send)

        # ── 5) 会话解析（§7 唯一校验点：Cookie 或 header 任一载体）────────────
        #    先于登录分流：已持会话（如壳握手会话）不得被 302 /login 截走。
        ident = sessions.resolve(cookie_token(scope) or _header(scope, "x-myapp-token") or None)
        scope["identity"] = ident
        if ident is not None:
            return await inner(scope, receive, send)

        # ── 6) 未登录分流（§9.6 约定 3：/api/* 401 JSON；页面 302 登录）───────
        if require_session:
            if want_login and not path.startswith("/api/"):
                return await _redirect(send, "/login")
            return await _json(send, 401, {"error": "unauthorized"})

        return await inner(scope, receive, send)

    async def app(scope, receive, send):
        if scope["type"] != "http":
            return await inner(scope, receive, send)
        if scope["path"] == "/healthz":              # 心跳豁免恒在最前（§6 探测依赖）
            return await _json(send, 200, {"ok": True})
        return await gate(scope, receive, send)

    return app
