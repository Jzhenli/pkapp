"""applocal 认证层单测（NETWORK_AUTH_DESIGN.md ★v1.2★ §5–§9）。

覆盖：session（PBKDF2/用户表/会话滑动过期/限速/Cookie 载体）、rbac（Identity/
模式表/require/ fail-closed）、_gate lan 门全链（内置初始 admin、登录/登出/
握手会话化/provision 零触摸建钥/?handshake= 窄豁免/auth=none/dev 权限覆盖报告 §9.3）。
ASGI 直接驱动（_runx），零额外依赖。
"""
import asyncio
import json
import os
import sys
import time
from dataclasses import replace

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from applocal import ContractError, _core, _env
from applocal import rbac
from applocal import session as sess
from applocal._gate import _DevCoverage, build_lan_app

from test_contract import env  # noqa: F401  (env fixture 复用：MYAPP_* 模拟)


# ---------------------------------------------------------------- 工具
def _runx(app, method="GET", path="/", headers=None, body=b"",
          identity=None, query=b""):
    scope = {"type": "http", "method": method, "path": path, "query_string": query,
             "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]}
    if identity is not None:
        scope["identity"] = identity

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    msgs = []

    async def send(m):
        msgs.append(m)

    asyncio.run(app(scope, receive, send))
    hdrs = {k.decode("latin-1").lower(): v.decode("latin-1")
            for k, v in msgs[0].get("headers", [])}
    payload = b"".join(m.get("body", b"") for m in msgs[1:])
    return msgs[0]["status"], payload, hdrs


async def _id_app(scope, receive, send):
    ident = scope.get("identity")
    body = json.dumps({"user": (ident or {}).get("user"),
                       "perms": (ident or {}).get("perms")}).encode()
    await _core._respond(send, 200, "application/json", body)


def _lan_cfg(env, *, dev=False, local_auth=True, auth=("login",),
             local_roles=("*",), provision_roles=("*",)):
    base = _env.load_env(refresh=True)
    net = _env.Network(enabled=True, local_auth=local_auth, bind="127.0.0.1",
                       session_days=7, auth=auth, local_roles=local_roles,
                       provision_roles=provision_roles)
    paths = replace(base.paths,                    # _lan_cfg 缺省恒给握手路径（文件有无另说）
                    handshake_file=str(env / "cache" / "handshake"))
    return _env.Cfg(paths=paths,
                    runtime=_env.Runtime(platform="windows", version="1.4.2", dev=dev),
                    network=net)


def _gate(env, app=None, *, roles=None, perms=None, **kw):
    os.makedirs(env / "dist", exist_ok=True)
    return build_lan_app(app or _id_app, _lan_cfg(env, **kw),
                         roles_table=roles or {}, route_perms=perms)


def _login(app, user="admin", pw="123456"):
    s, _, hdrs = _runx(app, "POST", "/login",
                       body=f"user={user}&password={pw}".encode())
    assert s == 302 and "sid=" in hdrs.get("set-cookie", "")
    return hdrs["set-cookie"].split(";")[0]        # sid=<token>


# ---------------------------------------------------------------- env：dev 开关
def test_env_dev_flag(env, monkeypatch):
    assert _env.load_env(refresh=True).runtime.dev is False
    monkeypatch.setenv("MYAPP_DEV", "1")
    assert _env.load_env(refresh=True).runtime.dev is True


def test_env_network_auth_none_exclusive(env, monkeypatch):
    """与 appspec validate 同规（§10）：none 独占，env/manifest 层同 fail-fast。"""
    monkeypatch.setenv("MYAPP_LAN", "1")
    monkeypatch.setenv("MYAPP_AUTH", "login,none")
    with pytest.raises(ContractError, match="共存"):
        _env.load_env(refresh=True)


def test_env_network_session_days_fail_fast(env, monkeypatch):
    """session_days 非法 → ContractError，不静默钳制。"""
    monkeypatch.setenv("MYAPP_LAN", "1")
    monkeypatch.setenv("MYAPP_SESSION_DAYS", "0")
    with pytest.raises(ContractError, match="session_days"):
        _env.load_env(refresh=True)


# ---------------------------------------------------------------- session 层
def test_password_roundtrip_and_malformed_stored():
    h = sess.hash_password("s3cret!")
    assert h.startswith("pbkdf2$100000$")          # PBKDF2-HMAC-SHA256 100k（★v1.1★）
    assert sess.verify_password("s3cret!", h)
    assert not sess.verify_password("wrong", h)
    assert not sess.verify_password("x", "garbage")  # 坏存储串 → False 而非抛
    assert not sess.verify_password("x", "")


def test_verify_missing_user_runs_pbkdf2(tmp_path):
    """F3：缺失用户与错误密码等耗时——用户名存在性不经时序外泄。"""
    st = sess.UserStore(str(tmp_path))
    st.create("alice", "pw123456", [])
    t0 = time.perf_counter()
    assert st.verify("nobody", "whatever") is None
    t_missing = time.perf_counter() - t0
    t0 = time.perf_counter()
    assert st.verify("alice", "wrongpass") is None
    t_wrong = time.perf_counter() - t0
    assert t_missing > 0.02                        # 确实跑了 PBKDF2（首查含生成）
    t0 = time.perf_counter()
    assert st.verify("nobody2", "whatever") is None
    t_missing2 = time.perf_counter() - t0
    assert t_missing2 > 0.02                       # 假 hash 已复用，仍等价耗时
    assert t_wrong > 0.02 and st.verify("alice", "pw123456")


def test_userstore_lifecycle(tmp_path):
    st = sess.UserStore(str(tmp_path))
    assert not st.exists()
    st.create("alice", "pw123456", ["admin"])
    st.create("bob", "pw123456", ["operator"])
    assert st.exists()
    rec = st.verify("alice", "pw123456")
    assert rec and rec["roles"] == ["admin"]
    assert st.verify("alice", "nope") is None
    assert st.set_password("alice", "newpass9")
    assert st.verify("alice", "newpass9") and st.verify("alice", "pw123456") is None
    assert st.remove("bob") and not st.remove("bob")   # 二次删除 False
    assert set(st.all()) == {"alice"}


def test_userstore_reload_on_external_write(tmp_path):
    """方案A：应用后端运行中建/改/删用户，门的 UserStore 免重启可见（mtime 检测）。"""
    gate_st = sess.UserStore(str(tmp_path))
    gate_st.create("admin", "pw123456", ["admin"])     # 门种子（构造期）
    app_st = sess.UserStore(str(tmp_path))             # 应用自己的实例（同 data_dir）
    app_st.create("op", "op-pass-9", ["operator"])     # 运行中新增用户
    assert gate_st.verify("op", "op-pass-9") is not None       # 门立即可认证，无需重启
    app_st.set_password("admin", "new-pass-7")         # 应用端改密
    assert gate_st.verify("admin", "pw123456") is None
    assert gate_st.verify("admin", "new-pass-7") is not None
    app_st.remove("op")                                # 应用端删用户
    assert gate_st.verify("op", "op-pass-9") is None


def test_userstore_corrupt_file_first_install(tmp_path):
    (tmp_path / "users.json").write_text("{not json", encoding="utf-8")
    assert not sess.UserStore(str(tmp_path)).exists()   # 损坏 → 首装语义（铁律）


def test_userstore_rejects_duplicate_and_empty(tmp_path):
    st = sess.UserStore(str(tmp_path))
    st.create("a", "pw123456", [])
    with pytest.raises(ValueError):
        st.create("a", "pw123456", [])
    with pytest.raises(ValueError):
        st.create("", "pw123456", [])


def test_userstore_atomic_write_no_tmp(tmp_path):
    sess.UserStore(str(tmp_path)).create("a", "pw123456", [])
    assert [f for f in os.listdir(tmp_path) if ".tmp" in f] == []


def test_sessionstore_roundtrip_and_sliding(tmp_path, monkeypatch):
    t = {"now": 1000.0}
    monkeypatch.setattr(sess.time, "time", lambda: t["now"])   # 假时钟：滑动续期可断言
    st = sess.SessionStore(str(tmp_path), ttl_s=100)
    tok = st.create("u", ["admin"], ["*"])
    assert st.resolve(tok) == {"user": "u", "roles": ["admin"], "perms": ["*"]}
    t["now"] += 50
    st.resolve(tok)                                     # 滑动续期（内存）
    t["now"] += 11                                      # 跨过 60s 落盘节流
    st.resolve(tok)                                     # 此时才落盘（避免每请求写盘）
    rec = json.loads((tmp_path / "sessions.json").read_text())[tok]
    assert rec["expires"] == 1161.0                     # 续到 now+ttl
    st2 = sess.SessionStore(str(tmp_path), ttl_s=100)   # 重启：按落盘续期值继续
    t["now"] += 100
    assert st2.resolve(tok) is not None                 # 未续期落盘的话此处已过期


def test_sessionstore_expired_dropped(tmp_path):
    st = sess.SessionStore(str(tmp_path), ttl_s=-1)     # 立即过期
    tok = st.create("u", [], [])
    assert st.resolve(tok) is None
    assert tok not in json.loads((tmp_path / "sessions.json").read_text())


def test_sessionstore_drop_and_corrupt(tmp_path):
    tok = sess.SessionStore(str(tmp_path)).create("u", [], [])
    st2 = sess.SessionStore(str(tmp_path))
    st2.drop(tok)
    assert st2.resolve(tok) is None
    (tmp_path / "sessions.json").write_text("bad", encoding="utf-8")
    assert sess.SessionStore(str(tmp_path)).resolve(tok) is None   # 解析失败按未登录（铁律）


def test_ratelimiter_lock_and_reset():
    rl = sess.RateLimiter()
    for _ in range(4):
        rl.fail("1.1.1.1")
    assert not rl.locked("1.1.1.1")
    rl.fail("1.1.1.1")                                  # 第 5 次 → 锁定
    assert rl.locked("1.1.1.1")
    rl.reset("1.1.1.1")
    assert not rl.locked("1.1.1.1")


def test_cookie_flags_and_parse():
    h = sess.cookie_header("TOK", 60)
    assert "sid=TOK" in h and "HttpOnly" in h and "SameSite=Strict" in h
    assert "Path=/" in h and "Max-Age=60" in h
    assert "Max-Age=0" in sess.cookie_clear_header()
    scope = {"headers": [(b"cookie", b"a=1; sid=TOK; b=2")]}
    assert sess.cookie_token(scope) == "TOK"
    assert sess.cookie_token({"headers": [(b"cookie", b"sid=")]}) is None
    assert sess.cookie_token({"headers": []}) is None


# ---------------------------------------------------------------- rbac 层
ROLES = {"admin": {"*"}, "operator": {"device.read"}}


def test_roles_to_perms():
    assert rbac.roles_to_perms(["operator"], ROLES) == ["device.read"]
    assert rbac.roles_to_perms(["nope"], ROLES) == []   # 未知角色 → 空（fail-closed）


def test_can():
    assert rbac.can({"perms": ["*"]}, "anything")
    assert rbac.can({"perms": ["device.read"]}, "device.read")
    assert not rbac.can({"perms": ["device.read"]}, "device.write")
    assert not rbac.can(None, "device.read")
    assert rbac.can(None, None) and rbac.can({"perms": []}, None)  # perm=None 恒真（公开）


def test_match_route_table():
    table = [
        (("GET", "/api/x"), "x.read"),
        (("POST", "/api/x"), "x.write"),
        ("/api/dev/*/status", "d.status"),              # 段通配
        ("/api/files/*", "f.list"),                     # 末尾 * = 前缀
        ("/api/pub", None),                             # 公开行
    ]
    assert rbac.match_route(table, "GET", "/api/x") == ("x.read", 0)
    assert rbac.match_route(table, "POST", "/api/x") == ("x.write", 1)
    assert rbac.match_route(table, "DELETE", "/api/x") == (None, -1)   # 方法不符
    assert rbac.match_route(table, "GET", "/api/dev/42/status") == ("d.status", 2)
    assert rbac.match_route(table, "GET", "/api/files/a/b") == ("f.list", 3)
    assert rbac.match_route(table, "GET", "/api/pub") == (None, 4)
    assert rbac.match_route(table, "GET", "/api/pubx") == (None, -1)   # 精确匹配不粘连
    assert rbac.match_route(table, "GET", "/api/y") == (None, -1)


def test_require_reports_and_raises():
    events = []
    scope = {"identity": {"perms": ["device.read"]}, "dev_report": events.append,
             "method": "GET", "path": "/api/d"}
    rbac.require(scope, "device.read")                  # 放行 → imperative 事件
    assert events[-1]["source"] == "imperative"
    with pytest.raises(rbac.Forbidden):
        rbac.require(scope, "device.write")             # 拒绝 → deny 事件
    assert events[-1]["source"] == "deny"
    assert len(events) == 2
    rbac.require({"identity": {"perms": ["*"]}}, "x")   # 无 dev_report 钩子也正常


def test_rbac_gate_fail_closed_unrouted():
    reached = []

    async def inner(scope, receive, send):
        reached.append(scope["path"])
        await _core._respond(send, 200, "text/plain", b"ok")

    app = rbac.rbac_gate(inner, [("/api/x", "x.read")])
    s, body, _ = _runx(app, path="/api/y")
    assert s == 403 and b"(unrouted)" in body
    assert not reached                                  # fail-closed：不透传 inner


def test_rbac_gate_rule_hit_public_and_denied():
    async def inner(scope, receive, send):
        await _core._respond(send, 200, "text/plain", b"ok")

    app = rbac.rbac_gate(inner, [("/api/pub", None), ("/api/x", "x.read")])
    assert _runx(app, path="/api/pub", identity={"perms": []})[0] == 200   # 公开行
    s, body, _ = _runx(app, path="/api/x")              # 无 identity → deny
    assert s == 403 and b"x.read" in body


def test_rbac_gate_dev_report_events():
    events = []

    async def inner(scope, receive, send):
        await _core._respond(send, 200, "text/plain", b"ok")

    app = rbac.rbac_gate(inner, [("/api/x", "x.read")], dev_report=events.append)
    _runx(app, path="/api/x", identity={"perms": ["x.read"]})   # rule#0
    _runx(app, path="/api/x")                                   # deny
    _runx(app, path="/api/y")                                   # unrouted
    assert [e["source"] for e in events] == ["rule#0", "deny", "unrouted"]


def test_dev_coverage_dedupe_and_mark(capsys):
    rep = _DevCoverage()
    rep({"method": "GET", "path": "/a", "perm": "p", "source": "rule#0"})
    rep({"method": "GET", "path": "/a", "perm": "p", "source": "rule#0"})      # 同判定去重
    rep({"method": "GET", "path": "/a", "perm": None, "source": "unrouted"})   # 判定变化再印
    err = capsys.readouterr().err
    assert err.count("[auth-coverage]") == 2
    assert "rule#0" in err and "未路由" in err


# ---------------------------------------------------------------- lan 门全链
def test_lan_healthz_exempt(env):
    app = _gate(env)
    assert _runx(app, path="/healthz")[0] == 200        # 心跳恒豁免（最外层）


def test_login_page_dist_override_and_fallback(env):
    """UI 归 dist（★v1.2★）：dist/login.html 存在 → 原样回（no-store）；缺失 → 内置兜底页。"""
    app = _gate(env)
    s, body, hdrs = _runx(app, path="/login")           # 无 login.html → 内置兜底页
    assert s == 200 and b"<form" in body
    (env / "dist" / "login.html").write_text(
        "<!doctype html><div id=app>vue-login</div>", encoding="utf-8")
    s, body, hdrs = _runx(app, path="/login")           # Vue 登录页优先（自包含，无 /assets 引用）
    assert s == 200 and b"vue-login" in body and b"<form" not in body
    assert hdrs.get("cache-control") == "no-store"      # 登录页不缓存


def test_admin_seeded_default_password(env, capsys):
    app = _gate(env)                                    # 门构造即种初始管理员
    err = capsys.readouterr().err
    assert "初始管理员" in err and "123456" in err      # 一次性提示（改密归应用后端）
    cookie = _login(app)                                # admin/123456 可直接登录
    s, body, _ = _runx(app, path="/api/x", headers={"Cookie": cookie})
    assert s == 200 and json.loads(body)["user"] == "admin"
    s, _, _ = _runx(app, "POST", "/login", body=b"user=admin&password=WRONG")
    assert s == 401
    users = json.loads((env / "data" / "users.json").read_text())
    assert set(users) == {"admin"}                      # 不再提供用户 CRUD


def test_login_logout_and_carriers(env):
    app = _gate(env)
    cookie = _login(app)
    s, body, _ = _runx(app, path="/api/x", headers={"Cookie": cookie})
    assert s == 200 and json.loads(body)["user"] == "admin"     # Cookie 载体 → identity
    token = cookie.split("=", 1)[1]
    s, body, _ = _runx(app, path="/api/x", headers={"X-MYAPP-Token": token})
    assert s == 200                                             # header 载体同效
    s, body, _ = _runx(app, "POST", "/login", body=b"user=admin&password=BAD")
    assert s == 401 and "错误".encode() in body
    s, _, hdrs = _runx(app, "POST", "/logout", headers={"Cookie": cookie})
    assert s == 302 and "Max-Age=0" in hdrs.get("set-cookie", "")
    s, _, _ = _runx(app, path="/api/x", headers={"Cookie": cookie})
    assert s == 401                                             # 会话已销毁


def test_valid_session_skips_login_redirect(env):
    os.makedirs(env / "data", exist_ok=True)
    st = sess.SessionStore(str(env / "data"), ttl_s=3600)
    tok = st.create("boot", ["admin"], ["*"])
    app = _gate(env)                                    # 有效会话 + 未登录页面请求
    s, _, _ = _runx(app, path="/", headers={"Cookie": f"sid={tok}"})
    assert s == 200                                     # §7：会话解析先于登录分流


def test_unauthenticated_page_redirects_login(env):
    app = _gate(env)
    s, body, _ = _runx(app, "GET", "/login")            # 登录页可匿名
    assert s == 200 and "登录".encode() in body
    s, _, _ = _runx(app, path="/", headers={"Accept": "text/html"})
    assert s == 302                                     # 未登录页面 → /login
    s, body, _ = _runx(app, path="/api/x")
    assert s == 401 and b"unauthorized" in body         # §9.6 约定 3：/api/* 401 JSON


def test_handshake_entry_sessionized(env):
    hf = env / "cache" / "handshake"
    hf.parent.mkdir(exist_ok=True)
    app = _gate(env, local_auth=False)
    hf.write_text("CODE-1", encoding="utf-8")
    s, body, hdrs = _runx(app, "POST", "/auth",
                          body=json.dumps({"handshake": "CODE-1"}).encode())
    assert s == 200 and json.loads(body) == {"ok": True}
    assert "sid=" in hdrs.get("set-cookie", "")         # ★收敛★：Cookie 是唯一载体（响应体无 token）
    assert not hf.exists()                              # 用后作废
    assert _runx(app, "POST", "/auth",
                 body=json.dumps({"handshake": "CODE-1"}).encode())[0] == 403
    app2 = _gate(env, local_auth=True)                  # 部署形态：握手入口封死
    hf.write_text("CODE-2", encoding="utf-8")
    assert _runx(app2, "POST", "/auth",
                 body=json.dumps({"handshake": "CODE-2"}).encode())[0] == 403


def test_handshake_query_narrow_bypass(env):
    hf = env / "cache" / "handshake"
    hf.parent.mkdir(exist_ok=True)
    app = _gate(env)
    # 无文件时任何 ?handshake= 都不豁免（★v1.2 F1 修复：码值必须与文件一致）
    s, _, _ = _runx(app, path="/", headers={"Accept": "text/html"}, query=b"handshake=XYZ")
    assert s == 302
    # 码值不符 → 静默落登录门（裸"键存在"豁免已封死）
    hf.write_text("CODE-1", encoding="utf-8")
    s, _, _ = _runx(app, path="/", headers={"Accept": "text/html"}, query=b"handshake=WRONG")
    assert s == 302
    s, _, _ = _runx(app, path="/", headers={"Accept": "text/html"}, query=b"handshake=")
    assert s == 302                                     # 空值不豁免
    # 码值一致 → 壳首航放行（且不消费文件——消费仅发生在 POST /auth）
    s, _, _ = _runx(app, path="/", headers={"Accept": "text/html"}, query=b"handshake=CODE-1")
    assert s == 200
    assert hf.exists() and hf.read_text() == "CODE-1"
    # 无握手参数 → 登录门照旧
    s, _, _ = _runx(app, path="/", headers={"Accept": "text/html"})
    assert s == 302


def test_provision_entry(env):
    app = _gate(env, auth=("provision",))               # 门构造即零触摸生成 lan.key（§11）
    key = (env / "data" / "lan.key").read_text().strip()
    assert len(key) == 64                               # 256bit hex
    s, body, _ = _runx(app, "POST", "/auth/provision",
                       body=json.dumps({"device_key": key}).encode())
    assert s == 200 and json.loads(body)["token"]
    s, _, _ = _runx(app, "POST", "/auth/provision",
                    body=json.dumps({"device_key": "WRONG"}).encode())
    assert s == 401
    s, _, _ = _runx(app, "POST", "/auth/provision", body=b"not json")
    assert s == 401                                     # 坏体 → 无区分 401（§11）
    os.remove(env / "data" / "lan.key")                 # 缺文件 → 401（重启补建）


def test_provision_disabled_when_not_selected(env):
    app = _gate(env, auth=("login",))
    assert _runx(app, "POST", "/auth/provision", body=b"{}")[0] == 404


def test_rate_limit_429(env):
    app = _gate(env)                                    # admin 已内置
    for _ in range(5):                                  # 5 次失败 → 锁 60s
        assert _runx(app, "POST", "/login", body=b"user=admin&password=BAD")[0] == 401
    s, _, _ = _runx(app, "POST", "/login", body=b"user=admin&password=123456")
    assert s == 429                                     # 锁定期内正确密码也 429


def test_auth_none_passthrough(env):
    app = _gate(env, auth=("none",))
    assert _runx(app, path="/api/x")[0] == 200          # §10：受控网段裸奔
    assert _runx(app, path="/setup")[0] == 200          # login 端点不存在 → 直达应用


def test_gate_rbac_chain(env):
    os.makedirs(env / "data", exist_ok=True)
    st = sess.UserStore(str(env / "data"))              # 门持有内存表：用户须在门构造前落盘
    st.create("op", "pw123456", ["operator"])
    st.create("root", "pw123456", ["admin"])
    app = _gate(env, roles={"operator": {"device.read"}},
                perms=[("/api/dev", "device.read"), ("/api/pub", None)])
    s, _, hdrs = _runx(app, "POST", "/login", body=b"user=root&password=pw123456")
    cookie = hdrs["set-cookie"].split(";")[0]           # admin → ["*"]
    s, _, hdrs = _runx(app, "POST", "/login", body=b"user=op&password=pw123456")
    op = hdrs["set-cookie"].split(";")[0]
    s, _, _ = _runx(app, path="/api/dev", headers={"Cookie": op})
    assert s == 200                                     # operator 有 device.read
    s, body, _ = _runx(app, path="/api/other", headers={"Cookie": op})
    assert s == 403 and b"(unrouted)" in body           # fail-closed：漏配即拒
    assert _runx(app, path="/api/pub", headers={"Cookie": op})[0] == 200
    assert _runx(app, path="/api/pub")[0] == 401        # 公开行 ≠ 免登录（仍过会话门）
    s, _, _ = _runx(app, path="/api/dev", headers={"Cookie": cookie})
    assert s == 200                                     # admin "*" 全通


def test_gate_unrouted_blocks_even_admin(env):
    app = _gate(env, perms=[("/api/x", "x.read")])
    cookie = _login(app)
    s, body, _ = _runx(app, path="/api/other", headers={"Cookie": cookie})
    assert s == 403 and b"(unrouted)" in body           # fail-closed 对 admin 同样生效


# ---------------------------------------------------------------- dev 覆盖报告（§9.3）
def test_gate_dev_coverage_report(env, capsys):
    app = _gate(env, dev=True, perms=[("/api/x", "x.read")])
    cookie = _login(app)
    _runx(app, path="/api/x", headers={"Cookie": cookie})       # rule#0
    _runx(app, path="/api/y", headers={"Cookie": cookie})       # unrouted → 403
    err = capsys.readouterr().err
    assert "[auth-coverage] GET /api/x perm=x.read (rule#0)" in err
    assert "GET /api/y" in err and "未路由" in err


def test_gate_dev_report_off_in_production(env, capsys):
    app = _gate(env, dev=False, perms=[("/api/x", "x.read")])
    cookie = _login(app)
    _runx(app, path="/api/y", headers={"Cookie": cookie})
    assert "[auth-coverage]" not in capsys.readouterr().err     # 生产不打报告


def test_gate_dev_report_require_imperative(env, capsys):
    async def req_app(scope, receive, send):
        rbac.require(scope, "device.read")              # 姿势 A：应用内命令式
        await _core._respond(send, 200, "application/json", b'{"ok":1}')

    app = _gate(env, dev=True, app=req_app)
    cookie = _login(app)
    s, _, _ = _runx(app, path="/api/d", headers={"Cookie": cookie})
    assert s == 200
    assert "(imperative)" in capsys.readouterr().err
