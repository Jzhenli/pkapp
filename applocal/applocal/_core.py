"""协议 A 运行期实现（SHELL_PROTOCOL.md §4-§9、§11④）。

- build_asgi_app：纯 ASGI 组装（/healthz、/auth 握手、静态豁免 + SPA 兜底、token 中间件）
  ——不依赖 starlette/fastapi，用户 app 只需是 ASGI callable；
- 探测式心跳：5s 真实 GET /healthz（2s 超时），成功才 seq+=1 并原子写 ready；
- bootstrap：壳唯一入口，五步时序（§4.2），uvicorn 惰性导入且在后台线程运行
  （线程模型注记①：bootstrap 返回后主线程立即 PyEval_SaveThread，永不持有 GIL）。
"""
from __future__ import annotations

import glob
import hmac
import importlib
import inspect
import json
import os
import sys
import threading
import time
import traceback
import urllib.request

from . import _env
from ._env import Cfg, ContractError

_AUTH_BODY_MAX = 4096    # /auth 请求体上限（loopback 也防异常大 body 吃内存）
_LOCK_WAIT_SEC = 10.0    # migrate 锁等待上限
_LOCK_STALE_SEC = 60.0   # 锁文件超过此年龄（或内容不可解析）→ 判为陈旧，自动接管

_MIME = {
    ".htm": "text/html; charset=utf-8", ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".mjs": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
    ".json": "application/json", ".svg": "image/svg+xml", ".png": "image/png",
    ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif",
    ".ico": "image/x-icon", ".webp": "image/webp", ".woff": "font/woff",
    ".woff2": "font/woff2", ".ttf": "font/ttf", ".map": "application/json",
    ".txt": "text/plain; charset=utf-8", ".webmanifest": "application/manifest+json",
}

# 心跳专用 opener：显式空代理表 → 强制直连。urlopen 会读系统/注册表代理，Windows 下
# ProxyOverride 无 127.0.0.1/<local> 例外时探测会被转发给代理 → 健康进程被误判死（§6）。
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


# ---------------------------------------------------------------- ready / diag
def write_ready(ready_file: str, port: int, seq: int, pid: int | None = None) -> dict:
    """原子写 ready（tmp + os.replace，同指纹规则①）。schema 见 SHELL_PROTOCOL §5。"""
    payload = {"ready": True, "port": int(port), "pid": int(pid or os.getpid()),
               "seq": int(seq), "ts": int(time.time())}
    os.makedirs(os.path.dirname(ready_file) or ".", exist_ok=True)
    tmp = f"{ready_file}.tmp{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f)
    os.replace(tmp, ready_file)
    return payload


def diag(stage: str, error: str, detail: str = "", recoverable: bool = True) -> dict:
    """写 diag.json（§9）。调用方须保证 error/detail 不含 token。"""
    payload = {"stage": stage, "error": str(error), "detail": str(detail)[:8000],
               "recoverable": bool(recoverable), "ts": int(time.time())}
    p = _env.load_env().paths.diag_file
    os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
    tmp = f"{p}.tmp{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False)
    os.replace(tmp, p)
    return payload


def read_diag() -> dict:
    try:
        with open(_env.load_env().paths.diag_file, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _clear_startup_diag(cfg: Cfg) -> None:
    """首跳成功后清掉 bootstrap 起始记录：diag.json 语义上只保留"当前失败原因"（§9）。

    不清则成功启动后残留 {"stage":"bootstrap","error":"starting ..."}，会误导错误页与排障。
    """
    p = cfg.paths.diag_file
    try:
        with open(p, encoding="utf-8") as f:
            d = json.load(f)
        if d.get("stage") == "bootstrap":
            os.remove(p)
    except (OSError, ValueError):
        pass


def _clear_healthz_diag(cfg: Cfg) -> None:
    """抖动恢复后清掉心跳自己写的失败记录（§9：diag 只留"当前失败原因"）。

    仅匹配 stage=runtime 且 error 以 healthz 开头的记录，不误删 on_background 等其他来源。
    """
    p = cfg.paths.diag_file
    try:
        with open(p, encoding="utf-8") as f:
            d = json.load(f)
        if d.get("stage") == "runtime" and str(d.get("error", "")).startswith("healthz"):
            os.remove(p)
    except (OSError, ValueError):
        pass


# ---------------------------------------------------------------- 端口
def _bind_socket(pref: int = 0):
    """绑定 127.0.0.1 并**持有** socket（pref 被占 → 让 OS 分配）；调用方负责 close。

    与 pick_port 的区别：返回的 socket 不关闭，可直接交给 uvicorn，消除"探测关闭后再 bind"的
    TOCTOU 窗口（§12.1）。注意：不设 SO_REUSEADDR——Windows 上它会允许他进程抢占同一端口。
    """
    import socket
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", pref))      # pref=0 → OS 自选端口
        return s
    except OSError:
        s.close()
    s = socket.socket()
    s.bind(("127.0.0.1", 0))             # 偏好被占 → 回退自选
    return s


def pick_port(pref: int = 0) -> int:
    """偏好端口被占用 → 让 OS 分配（§12.1"端口被占用时的重试写回"；实际端口进 ready）。"""
    s = _bind_socket(pref)
    try:
        return s.getsockname()[1]
    finally:
        s.close()


# ---------------------------------------------------------------- ASGI 组装
async def _respond(send, status: int, ctype: str, body: bytes, extra=(),
                   head: bool = False) -> None:
    """head=True：只回响应头（content-length 仍为实体长度），body 置空（静态 HEAD 豁免）。"""
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", ctype.encode()),
                            (b"content-length", str(len(body)).encode()), *extra]})
    await send({"type": "http.response.body", "body": b"" if head else body})


async def _json(send, status: int, obj: dict) -> None:
    await _respond(send, status, "application/json", json.dumps(obj).encode())


def _header(scope, name: str) -> str:
    for k, v in scope.get("headers") or []:
        if k.decode("latin-1").lower() == name:
            return v.decode("latin-1")
    return ""


def _wants_html(scope) -> bool:
    """浏览器导航请求（SPA 路由兜底用）；fetch/XHR 的 API 调用不走此分支。"""
    return "text/html" in _header(scope, "accept")


def _resolve_static(static_dir: str, path: str) -> str | None:
    """dist 内已存在的文件 → 返回绝对路径；防路径穿越；目录 → index.html。"""
    rel = (path or "/").lstrip("/") or "index.html"
    full = os.path.normpath(os.path.join(static_dir, rel))
    if not (full == os.path.normpath(static_dir) or full.startswith(os.path.normpath(static_dir) + os.sep)):
        return None
    if os.path.isdir(full):
        full = os.path.join(full, "index.html")
    return full if os.path.isfile(full) else None


def _read_static(path: str) -> bytes | None:
    """静态文件读取；isfile 之后被删等竞态/IO 错误 → None（视为未命中，不得 500）。

    同步全量读会阻塞事件循环——嵌入式 dist 由打包控制、均为小文件，loopback 场景可接受。
    """
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError:
        return None


def build_asgi_app(user_app, cfg: Cfg | None = None):
    """组装最终 ASGI：/healthz 豁免 → /auth 握手 → 静态豁免（含 SPA 兜底）→ token 中间件 → 用户 app。"""
    cfg = cfg or _env.load_env()
    rt, static = cfg.runtime, cfg.paths.static_dir
    if rt.strict_auth and not cfg.token:  # 空 token 会使比较恒真（实证）→ strict 下必须显式拒绝
        raise ContractError("strict_auth requires a non-empty MYAPP_TOKEN")
    if rt.strict_auth and not cfg.paths.handshake_file:  # §5.1：embedded 恒提供；缺失 → /auth 永远无法换到 token
        raise ContractError("strict_auth requires MYAPP_HANDSHAKE_FILE (otherwise /auth cannot mint a token)")

    async def _handshake(scope, receive, send):
        if not cfg.paths.handshake_file:
            return await _json(send, 403, {"error": "handshake disabled"})
        try:
            body = b""
            while True:
                m = await receive()
                body += m.get("body", b"")
                if len(body) > _AUTH_BODY_MAX:  # loopback 也防异常/恶意大 body 吃内存
                    return await _json(send, 413, {"error": "payload too large"})
                if not m.get("more_body"):
                    break
            code = json.loads(body or b"{}").get("handshake", "")
            if not isinstance(code, str):  # null/数字/bool/数组/对象 → 403，而非 .encode() AttributeError→500
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
            os.remove(cfg.paths.handshake_file)  # 用后作废；壳每次导航重写
        except OSError:
            pass  # 只读/已被并发删除：码已校验通过，删除失败不得让请求 500
        return await _json(send, 200, {"token": cfg.token})

    async def app(scope, receive, send):
        if scope["type"] != "http":
            return await user_app(scope, receive, send)
        method, path = scope["method"], scope["path"]
        if path == "/healthz":
            return await _json(send, 200, {"ok": True})
        if path == "/auth" and method == "POST":
            return await _handshake(scope, receive, send)
        if method in ("GET", "HEAD"):                 # HEAD 同属静态豁免面（§8①）
            hit = _resolve_static(static, path)
            if hit is None and _wants_html(scope):
                hit = os.path.join(static, "index.html")  # SPA 路由兜底
            if hit and os.path.isfile(hit):
                body = _read_static(hit)
                if body is not None:                      # isfile 后被删等竞态 → 视为未命中
                    ext = os.path.splitext(hit)[1].lower()    # 大小写不敏感：.HTML 也要正确 MIME + no-store
                    extra = [(b"cache-control", b"no-store")] if ext in (".html", ".htm") else ()
                    return await _respond(send, 200, _MIME.get(ext, "application/octet-stream"),
                                          body, extra,
                                          head=(method == "HEAD"))  # §8：index.html 禁缓存（升级白屏防护）
        if rt.strict_auth and not hmac.compare_digest(
                _header(scope, "x-myapp-token").encode("utf-8"), cfg.token.encode("utf-8")):
            return await _json(send, 401, {"error": "unauthorized"})
        return await user_app(scope, receive, send)

    return app


# ---------------------------------------------------------------- 心跳
def start_heartbeat(port: int, cfg: Cfg | None = None, interval: float = 5.0,
                    timeout: float = 2.0) -> threading.Thread:
    """探测式心跳（§6）：真实请求 /healthz，成功才 seq+=1 并原子写 ready；失败不 touch。"""
    cfg = cfg or _env.load_env()
    ready = cfg.paths.ready_file
    state = {"seq": 0}

    def _beat():
        fails = 0
        while True:
            time.sleep(interval)
            try:
                with _OPENER.open(f"http://127.0.0.1:{port}/healthz", timeout=timeout) as r:
                    ok = r.status == 200
            except Exception:
                ok = False  # 失败/hang/畸形响应 → 不 touch → 壳判死
                # 必须捕 Exception：http.client.HTTPException（BadStatusLine 等）不是 OSError 子类，
                # 漏掉会让心跳线程静默死亡 → ready 永不再更新 → 壳 30s 误判死
            if not ok:
                fails += 1
                if fails == 2:  # 连续 2 拍失败 → 写一次 diag 供错误页显示（此后不刷盘）
                    try:
                        diag("runtime", f"healthz probe failed {fails}x (port {port})",
                             detail="uvicorn startup failed or hung; server thread may be dead",
                             recoverable=True)
                    except Exception:
                        pass  # diag 不可写（cacheDir 被清等）不得反过来杀死心跳线程
                continue
            if fails:  # 抖动恢复：清掉自己写的 healthz 失败记录，不让过期失败误导错误页（§9）
                _clear_healthz_diag(cfg)
            fails = 0
            if state["seq"] == 0:
                _clear_startup_diag(cfg)   # 首跳成功 ⇒ 已健康，清掉 bootstrap 起始记录
            state["seq"] += 1
            try:
                write_ready(ready, port, state["seq"])
            except Exception:
                pass  # cacheDir 被清等；下一拍重写（同样不得杀死线程）

    t = threading.Thread(target=_beat, name="applocal-heartbeat", daemon=True)
    t.start()
    return t


# ---------------------------------------------------------------- migrate / 钩子
def _lock_is_stale(lock: str) -> bool:
    """陈旧锁判定：内容不可解析（上次写入未完成）或超过 _LOCK_STALE_SEC 未释放。

    以 ts 为准而非 pid 存活探测——跨平台 pid 探测不可靠（Windows os.kill(pid,0) 语义不一致）。
    """
    try:
        with open(lock, encoding="utf-8") as f:
            ts = float(f.read(64).split()[-1])
    except (OSError, ValueError, IndexError):
        return True
    return time.time() - ts > _LOCK_STALE_SEC


def _acquire_lock(lock: str, timeout: float | None = None) -> int:
    """独占锁（O_EXCL）；陈旧锁自动接管，避免上次进程被杀留下锁 → 新进程白等 10s 后启动失败。"""
    timeout = _LOCK_WAIT_SEC if timeout is None else timeout
    deadline = time.time() + timeout
    while True:
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            try:
                os.write(fd, f"{os.getpid()} {time.time()}".encode())  # 仅供排障
            except OSError:
                pass
            return fd
        except FileExistsError:
            if _lock_is_stale(lock):
                try:
                    os.remove(lock)  # 并发下可能多删一次，下一轮 O_EXCL 重新仲裁
                except OSError:
                    pass
                continue
            if time.time() > deadline:
                raise TimeoutError(f"migrate lock held >{timeout}s: {lock}")
            time.sleep(0.1)


def _release_lock(lock: str) -> None:
    """仅当锁内容仍是自己写入的 pid 时才删除：本进程若曾停顿 >_LOCK_STALE_SEC，
    锁可能已被他人当陈旧锁接管并重写——此时不得误删他人持有的锁。
    内容不可解析（自家 os.write 失败留空）→ 不删，交由陈旧判定路径（视为 stale）回收。
    """
    try:
        with open(lock, encoding="utf-8") as f:
            mine = int(f.read(64).split()[0]) == os.getpid()
    except (OSError, ValueError, IndexError):
        return
    if mine:
        try:
            os.remove(lock)
        except OSError:
            pass


def migrate(steps: dict, target: int | None = None) -> int:
    """数据迁移（文件锁防并发）：steps={版本号: 回调}，按序升版到 target（缺省=max）。

    注意：全部步骤总耗时须 < _LOCK_STALE_SEC（60s）——超过即会被其他进程当陈旧锁
    接管而失去互斥；超长迁移请拆分为多步、各自快速返回。
    """
    cfg = _env.load_env()
    os.makedirs(cfg.paths.data_dir, exist_ok=True)
    marker = os.path.join(cfg.paths.data_dir, "schema.txt")
    lock = os.path.join(cfg.paths.data_dir, ".migrate.lock")
    fd = _acquire_lock(lock)
    try:
        cur = _read_schema(marker)
        if target is None:
            target = max(steps) if steps else cur
        for v in sorted(steps):
            if cur < v <= target:
                steps[v]()
                cur = v
                _write_schema(marker, v)
        return cur
    finally:
        os.close(fd)
        _release_lock(lock)


def _read_schema(marker: str) -> int:
    try:
        with open(marker, encoding="utf-8") as f:
            return int(f.read().strip() or 0)
    except (OSError, ValueError):
        return 0


def _write_schema(marker: str, v: int) -> None:
    tmp = f"{marker}.tmp{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(str(v))
    os.replace(tmp, marker)


_bg_hooks: list = []


def on_background(callback=None):
    """Android 生命周期钩子（WAL checkpoint 等）：传回调=注册；无参=触发全部（壳经 JNI 调用）。"""
    if callback is not None:
        _bg_hooks.append(callback)
        return callback
    for cb in list(_bg_hooks):
        try:
            cb()
        except Exception:
            try:
                diag("runtime", f"background hook failed: {cb!r}",
                     detail=traceback.format_exc(), recoverable=True)
            except Exception:
                pass  # diag 不可用（cache 被清/env 缺失）不得中断剩余钩子（WAL checkpoint 等）
    return None


# ---------------------------------------------------------------- 嵌入态修正 / 平台探测
def set_process_title(name: str = "myapp") -> bool:
    """Linux 进程名探测（协议 B.y）：setproctitle 缺失静默跳过。"""
    try:
        import setproctitle
        setproctitle.setproctitle(name)
        return True
    except ImportError:
        return False


def _inject_native(lib_dir: str | None) -> None:
    """Android so 注入（§4.2 步骤 2 简版）：RTLD_GLOBAL 预载 + sys.path 前插；
    完整 meta-path finder 以 serious_python 蓝本在 M2 落地。"""
    if not lib_dir or not os.path.isdir(lib_dir):
        return
    if lib_dir not in sys.path:
        sys.path.insert(0, lib_dir)
    import ctypes
    for so in sorted(glob.glob(os.path.join(lib_dir, "*.so"))):
        try:
            ctypes.CDLL(so, mode=ctypes.RTLD_GLOBAL)
        except OSError:
            pass


# ---------------------------------------------------------------- bootstrap
def bootstrap(entry: str = "app.main:app") -> int:
    """壳唯一入口（§4.2 五步）。返回实际监听端口；ready 由心跳线程负责。"""
    cfg = _env.load_env()
    rt = cfg.runtime
    if rt.platform == "linux":                     # 步骤 0（§4.2：仅 Linux）
        set_process_title("myapp")
    sys.argv = [os.path.basename(sys.executable) or "myapp"]  # 步骤 0′（R25 嵌入态修正）
    if os.path.isdir(cfg.paths.app_dir) and cfg.paths.app_dir not in sys.path:
        sys.path.append(cfg.paths.app_dir)         # 步骤 1：追加到最后（§2.1③ stdlib/依赖优先；
                                                   # insert(0) 会让用户目录 shadow 标准库——已实证）
    _inject_native(rt.native_lib_dir)              # 步骤 2：Android so 注入
    diag("bootstrap", f"starting version={rt.version} platform={rt.platform}")
    try:
        mod_name, _, attr = entry.partition(":")
        user_app = getattr(importlib.import_module(mod_name), attr or "app")
    except Exception as e:                         # import 失败 → diag → 向壳上抛（非零退出）
        diag("bootstrap", f"import {entry} failed: {e}",
             detail=traceback.format_exc(), recoverable=True)
        raise
    sock = _bind_socket(rt.port_pref)              # 步骤 3′：先绑定并持有，消除 bind 前的 TOCTOU 窗口
    port = sock.getsockname()[1]
    try:
        asgi_app = build_asgi_app(user_app, cfg)
        try:
            import uvicorn                         # 惰性：由用户应用自带，applocal 零强制依赖
        except Exception as e:                     # 缺依赖 → diag → 向壳上抛（否则错误页无因可查）
            diag("bootstrap", f"import uvicorn failed: {e}",
                 detail=traceback.format_exc(), recoverable=False)
            raise
    except BaseException:
        sock.close()                               # 起不来就别占着端口
        raise
    server = uvicorn.Server(uvicorn.Config(
        asgi_app, host="127.0.0.1", port=port, access_log=False, log_config=None))
    threading.Thread(target=_run_server, args=(server, sock),
                     name="applocal-uvicorn", daemon=True).start()
    start_heartbeat(port, cfg)                     # 步骤 5′：ready 由首跳成功点亮
    return port


def _run_server(server, sock) -> None:
    """后台线程入口：把已绑定 socket 交给 uvicorn（消除 TOCTOU）；老版本 uvicorn 回退自绑定。"""
    try:
        supports_sockets = "sockets" in inspect.signature(server.run).parameters
    except (TypeError, ValueError):
        supports_sockets = False
    try:
        if supports_sockets:
            server.run(sockets=[sock])             # asyncio 内部会 sock.listen(backlog)，无需自行监听
        else:
            sock.close()
            server.run()
    except BaseException:
        try:
            sock.close()
        except OSError:
            pass
        raise
