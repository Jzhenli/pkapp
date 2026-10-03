"""applocal 契约测试（SHELL_PROTOCOL.md §12.1：env 模拟，无真机）。

覆盖：路径解析、缺失必填变量抛 ContractError、manifest 解析、ready schema 字段
齐全与 seq 单调、端口被占用重试、鉴权/握手/静态豁免（ASGI 直接驱动，零额外依赖）、
migrate 文件锁、on_background、diag 读写、token 不泄漏。
"""
import asyncio
import json
import os
import socket
import sys
import threading
import time
import urllib.request

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import applocal
from applocal import ContractError, load_env
from applocal import _core, _env, _ndk

@pytest.fixture()
def env(tmp_path, monkeypatch):
    d = tmp_path
    vals = {
        "MYAPP_PLATFORM": "windows",
        "MYAPP_DATA_DIR": str(d / "data"),
        "MYAPP_CACHE_DIR": str(d / "cache"),
        "MYAPP_READY_FILE": str(d / "cache" / "ready"),
        "MYAPP_DIAG_FILE": str(d / "cache" / "diag.json"),
        "MYAPP_STATIC_DIR": str(d / "dist"),
        "MYAPP_VERSION": "1.4.2",
        "MYAPP_MANIFEST_PATH": str(d / "runtime" / "manifest"),
        "MYAPP_TOKEN": "T" * 32,
    }
    (d / "runtime").mkdir()
    (d / "runtime" / "manifest").write_text(
        "app_version = 1.4.2\npython_dll = python312.dll\n坏行无等号\n# comment\n",
        encoding="utf-8")
    for k, v in vals.items():
        monkeypatch.setenv(k, v)
    for k in ("MYAPP_LOG_DIR", "MYAPP_PORT", "MYAPP_HANDSHAKE_FILE",
              "MYAPP_NATIVE_LIB_DIR", "MYAPP_STRICT_AUTH", "MYAPP_DEV",
              "MYAPP_LAN", "MYAPP_AUTH"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(_env, "_cfg", None)
    return d


# ---------------------------------------------------------------- env 契约
def test_missing_required_env_raises(env, monkeypatch):
    monkeypatch.delenv("MYAPP_DATA_DIR")
    with pytest.raises(ContractError, match="MYAPP_DATA_DIR"):
        load_env(refresh=True)


def test_bad_platform_raises(env, monkeypatch):
    monkeypatch.setenv("MYAPP_PLATFORM", "freebsd")
    with pytest.raises(ContractError, match="MYAPP_PLATFORM"):
        load_env(refresh=True)


def test_paths_resolution_and_defaults(env):
    cfg = load_env(refresh=True)
    p = cfg.paths
    assert p.log_dir == os.path.join(p.cache_dir, "log")          # MYAPP_LOG_DIR 缺省规则
    assert p.app_dir == os.path.join(os.path.dirname(p.manifest_path), "app")
    assert os.path.isabs(p.data_dir)


def test_manifest_parse_tolerant(env):
    rt = load_env(refresh=True).runtime
    assert rt.manifest["app_version"] == "1.4.2"
    assert rt.manifest["python_dll"] == "python312.dll"
    assert len(rt.manifest) == 2                                   # 坏行/注释被跳过


def test_manifest_immutable_snapshot(env):
    rt = load_env(refresh=True).runtime
    with pytest.raises(TypeError):
        rt.manifest["hack"] = "x"                                  # 快照不可变：不得改坏全局缓存


def test_dev_embedded_same_contract(env, monkeypatch):
    # dev 契约（manifest 文件缺失 → {}）与 embedded 走同一 load_env，无特例分支
    os.remove(env / "runtime" / "manifest")
    assert load_env(refresh=True).runtime.manifest == {}


# ---------------------------------------------------------------- ready 契约
def test_write_ready_schema_and_seq_monotonic(env):
    ready = str(env / "cache" / "ready")
    a = _core.write_ready(ready, 8765, 1)
    b = _core.write_ready(ready, 8765, 2)
    assert set(a) == {"ready", "port", "pid", "seq", "ts"}         # 字段齐全（§5）
    assert a["ready"] is True and a["port"] == 8765 and a["seq"] == 1
    assert b["seq"] == a["seq"] + 1                                 # 单调递增（§5）
    with open(ready, encoding="utf-8") as f:
        on_disk = json.loads(f.read())
    assert on_disk == b
    assert not [f for f in os.listdir(os.path.dirname(ready)) if ".tmp" in f]  # 原子写无残留


# ---------------------------------------------------------------- 端口
def test_pick_port_retry_when_busy(env):
    with socket.socket() as blocker:
        blocker.bind(("127.0.0.1", 0))
        blocker.listen(1)
        busy = blocker.getsockname()[1]
        got = _core.pick_port(busy)                                 # 偏好被占 → 换口
        assert got != busy and got > 0
    assert _core.pick_port(busy) == busy                            # 空闲 → 用偏好


def test_bind_socket_strict_raises_when_busy(env):
    with socket.socket() as blocker:
        blocker.bind(("127.0.0.1", 0))
        blocker.listen(1)
        busy = blocker.getsockname()[1]
        with pytest.raises(ContractError, match="occupied"):
            _core._bind_socket(busy, "127.0.0.1", strict=True)      # 显式端口被占 → fail-fast
        s = _core._bind_socket(busy, "127.0.0.1")                   # 非 strict 保持回落
        assert s.getsockname()[1] != busy
        s.close()
    s = _core._bind_socket(busy, "127.0.0.1", strict=True)          # 空闲 → 用偏好
    assert s.getsockname()[1] == busy
    s.close()


def test_bind_socket_reuseaddr_posix_only(env):
    """★v1.2★ SO_REUSEADDR 仅 POSIX：TIME_WAIT 残留卡重绑（安卓实测必现）；
    Windows 语义排他故不设。活监听者互斥不受影响（strict 用例覆盖）。"""
    if sys.platform == "win32":
        pytest.skip("POSIX-only semantics")
    s = _core._bind_socket(0, "127.0.0.1")
    assert s.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR) == 1
    s.close()
    # TIME_WAIT 模拟：绑定→监听→主动连接→关闭后立即重绑同端口
    port = s.getsockname()[1]
    c = socket.socket(); c.connect(("127.0.0.1", port)); c.close()  # 死连接 → TIME_WAIT
    s.close()
    time.sleep(0.3)
    s2 = _core._bind_socket(port, "127.0.0.1", strict=True)         # 无 REUSEADDR 会 EADDRINUSE
    s2.close()


def test_ndk_ext_finder_maps_lib_prefixed_names(env, tmp_path):
    """★v1.2★ _ndk.NdkExtFinder：lib<name>{EXT_SUFFIX} → 原名导入（Android release
    安装器只抽 lib*.so；debuggable 豁免不可依赖）。find_spec 只定位不加载。"""
    so = tmp_path / "lib_struct.cpython-312.so"
    so.write_bytes(b"stub")
    finder = _ndk.NdkExtFinder(str(tmp_path))
    spec = finder.find_spec("_struct")
    assert spec is not None and spec.origin == str(so)
    assert finder.find_spec("_nope") is None
    assert finder.find_spec("_struct", path=["x"]) is None   # 仅顶层扩展模块


def test_ndk_register_idempotent_and_early(env, monkeypatch):
    """★v1.2★ register：目录不存在 → 跳过；存在（即使暂无文件）→ 注册一次（幂等）。"""
    monkeypatch.setattr(sys, "meta_path", sys.meta_path[:])
    _ndk.register(str(env / "nope"))                         # 目录不存在 → 不注册
    assert not any(isinstance(f, _ndk.NdkExtFinder) for f in sys.meta_path)
    _ndk.register(str(env))
    _ndk.register(str(env))                                  # 幂等
    finders = [f for f in sys.meta_path if isinstance(f, _ndk.NdkExtFinder)]
    assert len(finders) == 1


# ---------------------------------------- 端口偏好来源（env > manifest，★v1.2★ network_port）
def test_port_from_manifest(env):
    (env / "runtime" / "manifest").write_text(
        "app_version = 1.4.2\nnetwork_port = 48765\n", encoding="utf-8")
    assert load_env(refresh=True).runtime.port_pref == 48765


def test_port_env_overrides_manifest(env, monkeypatch):
    (env / "runtime" / "manifest").write_text(
        "app_version = 1.4.2\nnetwork_port = 48765\n", encoding="utf-8")
    monkeypatch.setenv("MYAPP_PORT", "48766")                       # env 优先（运维覆盖层）
    assert load_env(refresh=True).runtime.port_pref == 48766


def test_port_bad_value_raises(env, monkeypatch):
    monkeypatch.setenv("MYAPP_PORT", "eighty")
    with pytest.raises(ContractError, match="integer"):
        load_env(refresh=True)


# ---------------------------------------------------------------- ASGI（鉴权/握手/静态）
def _run(app, method="GET", path="/", headers=None, body=b""):
    scope = {"type": "http", "method": method, "path": path, "query_string": b"",
             "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]}

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


async def _ok_app(scope, receive, send):
    await _core._respond(send, 200, "application/json", b'{"api":true}')


def _cfg(env, strict, token="T" * 32, handshake=None):
    # handshake=None → 缺省：strict 按契约（§5.1 embedded 恒提供）给路径；dev 禁用（空串）
    if handshake is None:
        handshake = env / "cache" / "handshake" if strict else ""
    monkey_free = load_env(refresh=True)
    return _env.Cfg(
        paths=_env.Paths(
            data_dir=monkey_free.paths.data_dir, cache_dir=monkey_free.paths.cache_dir,
            log_dir=monkey_free.paths.log_dir, ready_file=monkey_free.paths.ready_file,
            diag_file=monkey_free.paths.diag_file,
            handshake_file=str(handshake),
            static_dir=monkey_free.paths.static_dir,
            manifest_path=monkey_free.paths.manifest_path,
            app_dir=monkey_free.paths.app_dir),
        runtime=_env.Runtime(platform="windows", version="1.4.2", strict_auth=strict),
        token=token)


class _Resp:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _FakeOpener:
    """_core._OPENER 替身：fn=None 恒 200；fn 给定则按其抛错/返回。"""

    def __init__(self, fn=None):
        self.fn = fn

    def open(self, url, timeout=None):
        if self.fn:
            return self.fn(url, timeout=timeout)
        return _Resp()


def test_healthz_exempt(env):
    os.makedirs(env / "dist")
    app = applocal.build_asgi_app(_ok_app, _cfg(env, strict=False))
    assert _run(app, path="/healthz")[0] == 200                      # 豁免且无 token 也可达


def test_strict_auth_401_with_token_200(env):
    os.makedirs(env / "dist")
    app = applocal.build_asgi_app(_ok_app, _cfg(env, strict=True))
    status, body, _ = _run(app, path="/api/x")
    assert status == 401 and b"T" * 32 not in body                   # token 不进响应体
    status, _, _ = _run(app, path="/api/x", headers={"X-MYAPP-Token": "T" * 32})
    assert status == 200


def test_handshake_exchange_one_time(env):
    os.makedirs(env / "dist")
    hs = env / "cache" / "handshake"
    hs.parent.mkdir(exist_ok=True)
    hs.write_text("ONE-TIME-CODE", encoding="utf-8")
    app = applocal.build_asgi_app(_ok_app, _cfg(env, strict=True, handshake=hs))
    body = json.dumps({"handshake": "WRONG"}).encode()
    assert _run(app, "POST", "/auth", body=body)[0] == 403           # 错码拒绝
    body = json.dumps({"handshake": "ONE-TIME-CODE"}).encode()
    status, resp, _ = _run(app, "POST", "/auth", body=body)
    assert status == 200 and json.loads(resp)["token"] == "T" * 32
    assert not hs.exists()                                           # 用后作废
    status, _, _ = _run(app, "POST", "/auth", body=body)
    assert status == 403                                             # 二次使用拒绝


def test_static_serve_and_spa_fallback(env):
    dist = env / "dist"
    dist.mkdir(exist_ok=True)
    (dist / "index.html").write_text("<html>idx</html>", encoding="utf-8")
    (dist / "assets").mkdir()
    (dist / "assets" / "app.js").write_text("console.log(1)", encoding="utf-8")
    app = applocal.build_asgi_app(_ok_app, _cfg(env, strict=True))   # strict 下静态也豁免
    status, body, _ = _run(app, path="/assets/app.js",
                           headers={"Accept": "*/*"})                # 静态文件命中（非导航）
    assert status == 200 and b"console.log" in body
    status, body, hdrs = _run(app, path="/login", headers={"Accept": "text/html"})
    assert status == 200 and b"idx" in body                          # SPA 路由兜底
    assert hdrs.get("cache-control") == "no-store"                   # §8 v1.1：index.html 禁缓存
    status, _, _ = _run(app, path="/../../etc/passwd")
    assert status == 401                                             # 穿越不落静态分支 → 走鉴权


def test_static_read_race_falls_through(env, monkeypatch):
    dist = env / "dist"
    dist.mkdir(exist_ok=True)
    (dist / "index.html").write_text("<html>idx</html>", encoding="utf-8")
    app = applocal.build_asgi_app(_ok_app, _cfg(env, strict=True))
    monkeypatch.setattr(_core, "_read_static", lambda p: None)       # isfile 后文件被删
    status, _, _ = _run(app, path="/index.html")
    assert status == 401                                             # 未命中 → 落鉴权，不得 500


def test_dev_non_strict_bypasses_auth(env):
    os.makedirs(env / "dist")
    app = applocal.build_asgi_app(_ok_app, _cfg(env, strict=False))
    assert _run(app, path="/api/x")[0] == 200                        # dev 默认旁路（§8）


def test_strict_requires_nonempty_token(env):
    os.makedirs(env / "dist")
    with pytest.raises(ContractError, match="MYAPP_TOKEN"):
        applocal.build_asgi_app(_ok_app, _cfg(env, strict=True, token=""))  # 空token恒真，禁用


def test_strict_requires_handshake_file(env):
    os.makedirs(env / "dist")
    with pytest.raises(ContractError, match="HANDSHAKE"):
        applocal.build_asgi_app(_ok_app, _cfg(env, strict=True, handshake=""))  # §5.1：embedded 恒提供


def test_non_ascii_token_and_handshake_safe(env):
    os.makedirs(env / "dist")
    hs = env / "cache" / "handshake"
    hs.parent.mkdir(exist_ok=True)
    hs.write_text("OK-CODE", encoding="utf-8")
    app = applocal.build_asgi_app(_ok_app, _cfg(env, strict=True, handshake=hs))
    body = json.dumps({"handshake": "√√"}).encode("utf-8")           # 非 ASCII 握手码
    assert _run(app, "POST", "/auth", body=body)[0] == 403           # 403 而非 TypeError→500
    status, _, _ = _run(app, path="/api/x", headers={"X-MYAPP-Token": "√"})
    assert status == 401                                             # 非 ASCII token 头 → 401 而非 500


def test_handshake_non_string_type_403(env):
    os.makedirs(env / "dist")
    hs = env / "cache" / "handshake"
    hs.parent.mkdir(exist_ok=True)
    hs.write_text("CODE", encoding="utf-8")
    app = applocal.build_asgi_app(_ok_app, _cfg(env, strict=True, handshake=hs))
    for bad in (123, True, ["x"], {"a": 1}):                         # null/缺键已走 not code → 403
        body = json.dumps({"handshake": bad}).encode()
        assert _run(app, "POST", "/auth", body=body)[0] == 403       # 非字符串 → 403 而非 500


def test_heartbeat_writes_diag_on_failure(env):
    ready = env / "cache" / "ready"
    free = _core.pick_port(0)
    applocal.start_heartbeat(free, _cfg(env, strict=False),
                             interval=0.05, timeout=0.2)             # 无服务监听 → 必失败
    time.sleep(0.6)
    d = applocal.read_diag()
    assert "healthz" in d.get("error", "") and d["stage"] == "runtime"  # 失败可观测（§6）
    assert not ready.exists()                                        # 失败不 touch ready


def test_heartbeat_opener_bypasses_system_proxy(env, monkeypatch):
    """系统代理（http_proxy 指向死端口）不得影响心跳直连探测（§6）。"""
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:1")           # 死代理：走代理必失败
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class _H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        with _core._get_opener().open(
                f"http://127.0.0.1:{srv.server_address[1]}/", timeout=2) as r:
            assert r.status == 200                                   # 直连成功 → 未走代理
    finally:
        srv.shutdown()
        srv.server_close()


# ---------------------------------------------------------------- diag / migrate / 钩子
def test_diag_roundtrip_and_no_token(env):
    _core.diag("bootstrap", "boom", detail="stack...", recoverable=False)
    d = applocal.read_diag()
    assert d["stage"] == "bootstrap" and d["error"] == "boom"
    assert d["recoverable"] is False and "ts" in d
    assert "T" * 32 not in json.dumps(d)                             # token 禁入 diag（§8）


def test_migrate_runs_steps_in_order(env):
    ran = []
    cur = applocal.migrate({1: lambda: ran.append(1), 3: lambda: ran.append(3),
                            2: lambda: ran.append(2)})
    assert ran == [1, 2, 3] and cur == 3
    marker = env / "data" / "schema.txt"
    assert marker.read_text(encoding="utf-8") == "3"
    applocal.migrate({4: lambda: ran.append(4)})
    assert ran == [1, 2, 3, 4] and applocal.migrate({}) == 4         # 增量与幂等


def test_on_background_register_and_fire(env):
    hits = []
    applocal.on_background(lambda: hits.append("wal"))
    applocal.on_background(lambda: (_ for _ in ()).throw(ValueError("x")))  # 坏钩子不炸
    applocal.on_background()
    assert hits == ["wal"]


def test_frozen_api_surface():
    assert set(applocal.__all__) >= {
        "bootstrap", "paths", "runtime", "native_lib_dir", "set_process_title",
        "migrate", "diag", "read_diag", "on_background", "build_asgi_app",
        "start_heartbeat", "write_ready"}


# ---------------------------------------------------------------- 复核修复回归
def test_migrate_target_is_respected(env):
    ran = []
    cur = applocal.migrate({1: lambda: ran.append(1), 2: lambda: ran.append(2),
                            3: lambda: ran.append(3)}, target=2)
    assert ran == [1, 2] and cur == 2                                # 显式 target 不得被忽略


def test_migrate_stale_lock_is_taken_over(env):
    data = env / "data"
    data.mkdir(parents=True, exist_ok=True)
    lock = data / ".migrate.lock"
    lock.write_text("99999 0", encoding="utf-8")                     # 上次进程被杀留下的陈旧锁
    t0 = time.time()
    assert applocal.migrate({1: lambda: None}) == 1
    assert time.time() - t0 < 5                                      # 不白等 10s 再 TimeoutError
    assert not lock.exists()


def test_migrate_live_lock_still_blocks(env, monkeypatch):
    monkeypatch.setattr(_core, "_LOCK_WAIT_SEC", 0.3)                 # 缩短等待，测试不必等 10s
    data = env / "data"
    data.mkdir(parents=True, exist_ok=True)
    lock = data / ".migrate.lock"
    lock.write_text(f"{os.getpid()} {time.time()}", encoding="utf-8")  # 新鲜锁：不得被当成陈旧
    with pytest.raises(TimeoutError, match="migrate lock"):
        applocal.migrate({1: lambda: None})
    assert _core._lock_is_stale(str(lock)) is False


def test_migrate_release_only_own_lock(env):
    data = env / "data"
    data.mkdir(parents=True, exist_ok=True)
    lock = data / ".migrate.lock"
    lock.write_text(f"999999 {time.time()}", encoding="utf-8")        # 他人新鲜锁
    _core._release_lock(str(lock))
    assert lock.exists()                                              # 停顿恢复后不得误删他人锁
    lock.write_text(f"{os.getpid()} {time.time()}", encoding="utf-8")
    _core._release_lock(str(lock))
    assert not lock.exists()                                          # 自己的可删


def test_relative_path_rejected(env, monkeypatch):
    for var in ("MYAPP_DATA_DIR", "MYAPP_CACHE_DIR", "MYAPP_STATIC_DIR",
                "MYAPP_READY_FILE", "MYAPP_DIAG_FILE"):
        orig = os.environ[var]
        monkeypatch.setenv(var, "relative/path")
        with pytest.raises(ContractError, match="absolute"):           # §2 绝对路径契约
            load_env(refresh=True)
        monkeypatch.setenv(var, orig)


def test_handshake_remove_failure_still_ok(env):
    hs = env / "cache" / "handshake"
    hs.parent.mkdir(parents=True, exist_ok=True)
    hs.write_text("CODE", encoding="utf-8")
    app = applocal.build_asgi_app(_ok_app, _cfg(env, strict=True, handshake=hs))
    os.chmod(hs, 0o444)                                              # 只读 → os.remove 必失败
    try:
        status, body, _ = _run(app, "POST", "/auth",
                               body=json.dumps({"handshake": "CODE"}).encode())
        assert status == 200 and json.loads(body)["token"] == "T" * 32  # 码已校验通过，删除失败不得 500
    finally:
        os.chmod(hs, 0o644)


def test_auth_body_limit(env):
    hs = env / "cache" / "handshake"
    hs.parent.mkdir(parents=True, exist_ok=True)
    hs.write_text("CODE", encoding="utf-8")
    app = applocal.build_asgi_app(_ok_app, _cfg(env, strict=True, handshake=hs))
    assert _run(app, "POST", "/auth", body=b"x" * (_core._AUTH_BODY_MAX + 1))[0] == 413


def test_head_static_and_case_insensitive_ext(env):
    dist = env / "dist"
    dist.mkdir(exist_ok=True)
    (dist / "index.html").write_text("<html>idx</html>", encoding="utf-8")
    (dist / "old.htm").write_text("<html>old</html>", encoding="utf-8")
    (dist / "PAGE.HTML").write_text("<html>big</html>", encoding="utf-8")
    app = applocal.build_asgi_app(_ok_app, _cfg(env, strict=True))
    status, body, hdrs = _run(app, "HEAD", "/index.html")
    assert status == 200 and body == b"" and hdrs["content-type"].startswith("text/html")
    status, _, hdrs = _run(app, "GET", "/old.htm")
    assert status == 200 and hdrs["content-type"].startswith("text/html")
    status, _, hdrs = _run(app, "GET", "/PAGE.HTML")                  # 大写扩展名：MIME 与 no-store 都生效
    assert status == 200 and hdrs["content-type"].startswith("text/html")
    assert hdrs.get("cache-control") == "no-store"


def test_heartbeat_survives_non_oserror(env, monkeypatch):
    import http.client

    def boom(*a, **k):
        raise http.client.BadStatusLine("garbage")                    # 非 OSError 子类

    monkeypatch.setattr(_core, "_OPENER", _FakeOpener(fn=boom))
    t = applocal.start_heartbeat(12345, _cfg(env, strict=False), interval=0.02, timeout=0.2)
    time.sleep(0.3)
    assert t.is_alive()                                               # 心跳线程不得被非 OSError 打死
    assert "healthz" in applocal.read_diag().get("error", "")


def test_startup_diag_cleared_after_first_ready(env, monkeypatch):
    _core.diag("bootstrap", "starting version=1.4.2 platform=windows")
    monkeypatch.setattr(_core, "_OPENER", _FakeOpener())
    applocal.start_heartbeat(12345, _cfg(env, strict=False), interval=0.02, timeout=0.2)
    deadline = time.time() + 3
    while not (env / "cache" / "ready").exists() and time.time() < deadline:
        time.sleep(0.05)
    assert json.loads((env / "cache" / "ready").read_text())["seq"] >= 1
    assert not (env / "cache" / "diag.json").exists()                 # 健康后不留 bootstrap 起始记录


def test_healthz_diag_cleared_on_recovery(env, monkeypatch):
    calls = {"n": 0}

    def flaky(url, timeout=None):
        calls["n"] += 1
        if calls["n"] <= 2:
            raise OSError("conn refused")                             # 前两拍失败 → 写 diag
        return _Resp()

    _core.diag("runtime", "healthz probe failed 2x (port 1)", detail="simulated")
    monkeypatch.setattr(_core, "_OPENER", _FakeOpener(fn=flaky))
    ready = env / "cache" / "ready"
    applocal.start_heartbeat(1, _cfg(env, strict=False), interval=0.02, timeout=0.2)
    deadline = time.time() + 3
    while not ready.exists() and time.time() < deadline:
        time.sleep(0.02)
    assert ready.exists()                                             # 抖动恢复成功
    assert not (env / "cache" / "diag.json").exists()                 # 过期失败记录已清（§9）


def _fake_uvicorn(monkeypatch, captured):
    """注入假 uvicorn 模块，捕获 Server.run 收到的 sockets/Config。

    bootstrap 直导 uvicorn.config/uvicorn.server（★启动优化★，跳过 CLI 面），
    故三个模块名都要进 sys.modules（config/server 以 package 形态挂在 uvicorn 下）。"""
    import types
    fake = types.ModuleType("uvicorn")
    fake.__path__ = []  # 标记为 package，使 from uvicorn.config import ... 可解析

    class Config:
        def __init__(self, app, **kw):
            captured["app"], captured["kw"] = app, kw

    class Server:
        def __init__(self, config):
            captured["config"] = config

        def run(self, sockets=None):
            captured["sockets"] = sockets
            captured["bound_port"] = sockets[0].getsockname()[1] if sockets else None

    fake.Config, fake.Server = Config, Server
    fake_config = types.ModuleType("uvicorn.config")
    fake_config.Config = Config
    fake_server = types.ModuleType("uvicorn.server")
    fake_server.Server = Server
    monkeypatch.setitem(sys.modules, "uvicorn", fake)
    monkeypatch.setitem(sys.modules, "uvicorn.config", fake_config)
    monkeypatch.setitem(sys.modules, "uvicorn.server", fake_server)
    return fake


def _prep_entry(env):
    app_dir = env / "runtime" / "app"
    app_dir.mkdir(parents=True, exist_ok=True)
    (app_dir / "main.py").write_text("app = object()\n", encoding="utf-8")


def test_bootstrap_hands_bound_socket_to_uvicorn(env, monkeypatch):
    _prep_entry(env)
    captured = {}
    _fake_uvicorn(monkeypatch, captured)
    monkeypatch.setattr(sys, "argv", list(sys.argv))                  # bootstrap 会改写 argv/path
    monkeypatch.setattr(sys, "path", list(sys.path))
    port = applocal.bootstrap("main:app")
    deadline = time.time() + 3
    while "sockets" not in captured and time.time() < deadline:
        time.sleep(0.05)
    assert captured["sockets"] and len(captured["sockets"]) == 1       # 预绑定 socket 直接交给 uvicorn
    assert port == captured["bound_port"] == captured["kw"]["port"]    # 上报端口 == 实际绑定端口（无 TOCTOU）
    assert captured["kw"]["host"] == "127.0.0.1" and captured["kw"]["access_log"] is False


def test_bootstrap_missing_uvicorn_writes_diag(env, monkeypatch):
    _prep_entry(env)
    monkeypatch.setitem(sys.modules, "uvicorn", None)                 # import uvicorn → ImportError
    monkeypatch.setattr(sys, "argv", list(sys.argv))
    monkeypatch.setattr(sys, "path", list(sys.path))
    with pytest.raises(ImportError):
        applocal.bootstrap("main:app")
    d = applocal.read_diag()
    assert "uvicorn" in d["error"] and d["recoverable"] is False       # 错误页有因可查（§6）
