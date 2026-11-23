"""pkapp dev [--strict-auth]：起 dev 服务（自动注入 MYAPP_*，SHELL_PROTOCOL §2 dev 契约）。

dev 契约：platform=宿主平台、data/cache/static=项目 .dev/（static 用项目 dist）、
port=8765、version=0.0.0-dev、manifest={}（空文件，非缺失）。
--strict-auth：embedded 模式静态 token 链（暴露"忘带 X-MYAPP-Token"的 401 bug）；
仅无 [network] 的项目可走（有 [network] 时 dev 直接起 lan 门 Cookie 会话，不经此路径）。
子进程内 applocal.bootstrap(entry)——dev 与 embedded 同一契约（协议 A §12.1）。
"""
from __future__ import annotations

import os
import secrets
import subprocess

from ..appspec import AppSpec, SpecError, load
from ..util import atomic_write

DEV_PORT = 8765
# 已装 applocal 版本 + editable 标记探测（对齐前置；editable = 源码调试契约层，绝不 clobber）
# 注：定位 dist-info 走 m.files()（公开 API，3.11+ 稳定）——Distribution.path 在
# 3.12 是私有 _path（3.14 才转正），真机冒烟踩过（AttributeError → probe 假失败）
_APPLOCAL_PROBE = """
import importlib.metadata as m, json
v = m.version('applocal')
e = False
for f in (m.files('applocal') or []):
    if str(f).endswith('direct_url.json'):
        try:
            with open(f.locate(), encoding='utf-8') as fh:
                e = bool(json.load(fh).get('dir_info', {}).get('editable'))
        except Exception:
            pass
        break
print(v, int(e))
"""
_PROBE_TIMEOUT = 60    # probe 有界（杀软扫描/解释器挂死不让 dev 卡死）
_ALIGN_TIMEOUT = 120   # pip 离线单 wheel 安装上界
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
    project_dir = os.path.abspath(project_dir)   # MYAPP_* 路径必须绝对（_env._abs 校验）
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
        "MYAPP_DEV": "1",                       # dev 权限覆盖报告（§9.3）等 dev 专属行为的开关
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
    # manifest：默认空文件（dev 契约 {} 非缺失）；[network] 配置 → network_* 键透传（§5）
    os.makedirs(env["MYAPP_DATA_DIR"], exist_ok=True)
    os.makedirs(env["MYAPP_CACHE_DIR"], exist_ok=True)
    os.makedirs(env["MYAPP_STATIC_DIR"], exist_ok=True)
    net_keys = spec.network.manifest_keys()
    if net_keys:
        atomic_write(env["MYAPP_MANIFEST_PATH"],
                     ("\n".join(f"{k} = {v}" for k, v in net_keys.items()) + "\n").encode())
    elif not os.path.exists(env["MYAPP_MANIFEST_PATH"]):
        atomic_write(env["MYAPP_MANIFEST_PATH"], b"")

    py = python or _venv_python(project)
    if py is None:
        print("[dev] 未找到项目 .venv——先 pkapp create 或用 --python 指定解释器")
        return 2
    try:
        _align_applocal(py)   # 契约层漂移自动对齐（有漂移才动手；成功/失败均有可见输出）
    except FileNotFoundError:
        pass                  # 坏 --python 路径：随后的 shim run 统一报"解释器不可用"

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


def _align_applocal(py: str) -> None:
    """契约层漂移自动对齐：工具内置 applocal wheel 新于当前解释器已装版本 →
    离线安装（--no-index --find-links 内置 wheel + 精确 pin）对齐到工具版本。

    - 仅契约层一个 wheel：秒级、完全离线、确定性；业务依赖一律不碰。
    - editable 安装（pip install -e applocal 源码调试契约层）绝不 clobber
      （direct_url.json 的 dir_info.editable 识别后跳过）。
    - 无内置 wheel（源码仓库形态）→ 整个检查跳过。
    - 对齐成功打印变更行（透明，非静默魔法）；失败回退提示模式。
    - probe/pip 均有 timeout（有界子进程惯例）——挂死不让 dev 卡死。
    """
    from .. import vendor
    want = vendor.applocal_wheel_version()
    wd = vendor.wheels_dir()
    if want is None or not wd:
        return
    try:
        r = subprocess.run([py, "-c", _APPLOCAL_PROBE],
                           capture_output=True, text=True, timeout=_PROBE_TIMEOUT)
    except subprocess.TimeoutExpired:
        return                      # 对齐是尽力而为：probe 超时静默让位主流程
    have = editable = None
    if r.returncode == 0:
        try:
            v, e = r.stdout.split()
            have, editable = v, e == "1"
        except ValueError:
            pass
    if editable:
        return
    if have is not None:
        from ..appspec._core import _ver_tuple
        if _ver_tuple(have) >= _ver_tuple(want):
            return
    try:
        s = subprocess.run([py, "-m", "pip", "install", "-q", "--disable-pip-version-check",
                            "--no-index", "--find-links", wd, f"applocal=={want}"],
                           capture_output=True, text=True, timeout=_ALIGN_TIMEOUT)
    except subprocess.TimeoutExpired:
        s = None
    if s is not None and s.returncode == 0:
        print(f"[dev] applocal {'missing' if have is None else have} → {want}"
              "（离线对齐工具内置 wheel）")
        return
    err = "" if s is None else s.stderr.strip()[-200:]
    print(f"[dev] applocal 自动对齐失败（内置 {want}，已装 {have or 'missing'}）——手动：\n"
          f"  \"{py}\" -m pip install -U applocal --find-links \"{wd}\"\n"
          f"  {err}")


def _venv_python(project: str) -> str | None:
    sub = "Scripts/python.exe" if os.name == "nt" else "bin/python"
    p = os.path.join(project, ".venv", sub)
    return p if os.path.isfile(p) else None
