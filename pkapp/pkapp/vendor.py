"""内置制品定位（pkapp/_vendor/）：wheel 安装形态随 pkapp 分发的预编译件。

目录由 scripts/vendor.py（CI release / 本地同一条命令）组装：
  _vendor/shell/MyApp.exe + WebView2Loader.dll   ← shell-windows/build 产物
  _vendor/wheels/*.whl                            ← applocal 离线 wheel（非 PyPI 私有件）
源码仓库形态 / 测试环境可能无 _vendor/——所有取用方必须容忍缺失（返回 None）。
"""
from __future__ import annotations

import os


def shell_exe() -> str | None:
    """包内置 Windows 壳（WebView2Loader.dll 恒同目录旁置）。"""
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "_vendor", "shell", "MyApp.exe")
    return p if os.path.isfile(p) else None


def wheels_dir() -> str | None:
    """包内置离线 wheel 目录（applocal 等非 PyPI 私有件的唯一随包入口）。"""
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_vendor", "wheels")
    return p if os.path.isdir(p) else None
