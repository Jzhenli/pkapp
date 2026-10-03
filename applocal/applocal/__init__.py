"""applocal — pkapp 契约层（协议 A：壳 ⇄ applocal；协议 C：applocal ⇄ 用户代码）。

独立纯 Python 包，零强制依赖（uvicorn 由用户应用自带、惰性导入）。
12 个冻结函数（§4.1：API 只加不改；差异吸收在函数内部；dev 与 embedded 同一契约）：

    bootstrap / paths / runtime / native_lib_dir / set_process_title /
    migrate / diag / read_diag / on_background / build_asgi_app /
    start_heartbeat / write_ready

事实源：docs/SHELL_PROTOCOL.md（协议 A）。
"""
import os as _os
import time as _time

_IMPORT_T0 = _time.perf_counter()  # 模块导入起点（__init__ 自身 + _core 链）

if _os.environ.get("MYAPP_NATIVE_LIB_DIR"):
    # ★v1.2★ Android W^X：finder 必须在 `from ._core import` 之前注册——
    # _core → base64 → struct → _struct 的导入链先于 bootstrap() 触发
    from ._ndk import register as _ndk_register
    _ndk_register(_os.environ["MYAPP_NATIVE_LIB_DIR"])

from ._core import (bootstrap, build_asgi_app, diag, migrate, on_background,
                    pick_port, read_diag, set_process_title, start_heartbeat,
                    write_ready)
from ._env import ContractError, load_env

__version__ = "0.1.0"

APP_DIR = "app"  # 保留常量：用户代码 import 根目录名


def paths():
    """路径服务（铁律 2：用户数据路径只经此处）。"""
    return load_env().paths


def runtime():
    """环境事实快照（platform/version/manifest/native_lib_dir/strict_auth/port_pref）。

    注意：不含 token——token 禁止进入可被打印/落盘的返回值（§8 禁令）。
    """
    return load_env().runtime


def native_lib_dir():
    """Android 原生库目录（lib/<abi>/）；桌面端返回 None。"""
    return load_env().runtime.native_lib_dir


try:  # 启动打点：import applocal 全链耗时（诊断用，绝不影响功能）
    with open(_os.path.join(_os.environ["MYAPP_CACHE_DIR"], "boot-timing.log"),
              "a", encoding="utf-8") as _f:
        _f.write(f"[{_time.strftime('%H:%M:%S')}] import applocal (module init): "
                 f"{_time.perf_counter() - _IMPORT_T0:.3f}s\n")
except Exception:
    pass


__all__ = [
    # 12 个冻结函数
    "bootstrap", "paths", "runtime", "native_lib_dir", "set_process_title",
    "migrate", "diag", "read_diag", "on_background", "build_asgi_app",
    "start_heartbeat", "write_ready",
    # 异常与工具（不算冻结函数，但属公开面）
    "ContractError", "load_env", "pick_port",
]
