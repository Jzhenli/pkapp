"""pkapp dev [--strict-auth]：起 dev 服务（自动注入 MYAPP_*，SHELL_PROTOCOL §2 dev 契约）。

dev 契约：platform=宿主平台、data/cache/static=项目 .dev/（static 用项目 dist）、
port=8765、version=0.0.0-dev、manifest={}（空文件，非缺失）。
--strict-auth：注入 token + 生产同款中间件 + 一次性握手码（暴露"忘带 X-MYAPP-Token"的 401 bug）。
子进程内 applocal.bootstrap(entry)——dev 与 embedded 同一契约（协议 A §12.1）。
"""
from __future__ import annotations

import os
import secrets
import subprocess

from ..appspec import AppSpec, SpecError, load
from ..util import atomic_write

DEV_PORT = 8765
_BOOTSTRAP_SHIM = """
import threading
import applocal

port = applocal.bootstrap({entry!r})
print(f"[pkapp dev] serving http://127.0.0.1:{{port}}", flush=True)
try:
    threading.Event().wait()   # uvicorn 在后台线程；主线程驻留（embedded 同款：壳驻留）
except KeyboardInterrupt:
    pass
"""


def build_dev_env(project_dir: str, spec: AppSpec, *, strict: bool,
                  port: int = DEV_PORT) -> tuple[dict[str, str], str | None]:
    """计算 MYAPP_* 环境注入表；返回 (env增量, strict 模式的握手码)。"""
    dev_dir = os.path.join(project_dir, ".dev")
    data_dir = os.path.join(dev_dir, "data")
    cache_dir = os.path.join(dev_dir, "cache")
    manifest_path = os.path.join(dev_dir, "manifest")
    static_dir = os.path.join(project_dir, spec.dist_dir)
    env = {
        "MYAPP_PLATFORM": spec_host_platform(),
        "MYAPP_DATA_DIR": data_dir,
        "MYAPP_CACHE_DIR": cache_dir,
        "MYAPP_READY_FILE": os.path.join(cache_dir, "ready"),
        "MYAPP_DIAG_FILE": os.path.join(cache_dir, "diag.json"),
        "MYAPP_STATIC_DIR": static_dir,
        "MYAPP_MANIFEST_PATH": manifest_path,   # {} 非缺失：写空文件
        "MYAPP_VERSION": "0.0.0-dev",
        "MYAPP_PORT": str(port),
    }
    handshake_code = None
    if strict:
        # 生产同款：token + 一次性握手码文件（token 禁止进 URL/日志——§8）
        token = secrets.token_hex(32)
        handshake_code = secrets.token_urlsafe(24)
        env["MYAPP_STRICT_AUTH"] = "1"
        env["MYAPP_TOKEN"] = token
        env["MYAPP_HANDSHAKE_FILE"] = os.path.join(dev_dir, "handshake")
    return env, handshake_code


def spec_host_platform() -> str:
    from ..appspec import host_platform
    return host_platform()


def cmd_dev(project: str, *, strict_auth: bool = False, port: int = DEV_PORT,
            python: str | None = None) -> int:
    try:
        spec = load(os.path.join(project, "pkapp.toml"))
    except SpecError as e:
        print(f"[dev] AppSpec 错误: {e}")
        return 2

    env, handshake_code = build_dev_env(project, spec, strict=strict_auth, port=port)
    # manifest={}（非缺失）+ 目录自愈
    os.makedirs(env["MYAPP_DATA_DIR"], exist_ok=True)
    os.makedirs(env["MYAPP_CACHE_DIR"], exist_ok=True)
    os.makedirs(env["MYAPP_STATIC_DIR"], exist_ok=True)
    if not os.path.exists(env["MYAPP_MANIFEST_PATH"]):
        atomic_write(env["MYAPP_MANIFEST_PATH"], b"")

    py = python or _venv_python(project)
    if py is None:
        print("[dev] 未找到项目 .venv——先 pkapp create 或用 --python 指定解释器")
        return 2

    full_env = dict(os.environ)
    full_env.update(env)
    if strict_auth:
        atomic_write(env["MYAPP_HANDSHAKE_FILE"], handshake_code.encode())
        print(f"[dev] strict-auth 已启用。浏览器打开（附一次性握手码）：\n"
              f"  http://127.0.0.1:{port}/?handshake={handshake_code}")
    print(f"[dev] platform={env['MYAPP_PLATFORM']} port={port} "
          f"entry={spec.entry} python={py}")

    shim = _BOOTSTRAP_SHIM.format(entry=spec.entry)
    try:
        r = subprocess.run([py, "-c", shim], env=full_env)
    except FileNotFoundError:
        print(f"[dev] 解释器不可用: {py}")
        return 2
    return r.returncode


def _venv_python(project: str) -> str | None:
    sub = "Scripts/python.exe" if os.name == "nt" else "bin/python"
    p = os.path.join(project, ".venv", sub)
    return p if os.path.isfile(p) else None
