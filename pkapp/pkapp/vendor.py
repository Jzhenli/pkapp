"""内置制品定位（pkapp/_vendor/）：wheel 安装形态随 pkapp 分发的预编译件。

目录由 scripts/vendor.py（CI release / 本地同一条命令）组装：
  _vendor/shell/MyApp.exe + WebView2Loader.dll   ← shell-windows/build 产物
  _vendor/wheels/*.whl                            ← applocal 离线 wheel（非 PyPI 私有件）
  _vendor/shell-linux/<arch>/<name>               ← launcher ELF（M3 阶段 2 条 5；
                                                    manylinux2014 容器编译产物）
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


def applocal_wheel_version() -> str | None:
    """内置 applocal wheel 的版本号（文件名 applocal-<ver>-*.whl 解析）——工具期望
    契约层版本的单一事实源：工具升级 → 内置 wheel 升级 → 期望版本自动抬升。
    规范发布恒为单 wheel（scripts/vendor.py 组装前 rmtree）；若手工放置多版本，
    按 PEP 440 元组取 max（字典序会错选："0.1.9" > "0.1.10"）。无 _vendor/
    （源码仓库形态）或目录内无 applocal wheel → None（调用方跳过比对）。"""
    d = wheels_dir()
    if not d:
        return None
    wheels = []
    for fn in os.listdir(d):
        parts = fn.split("-")
        if fn.endswith(".whl") and len(parts) >= 2 and parts[0] == "applocal":
            wheels.append(fn)
    if not wheels:
        return None
    return max(wheels, key=lambda fn: tuple(int(p) if p.isdigit() else -1
                                            for p in fn.split("-")[1].split("."))).split("-")[1]


def launcher_elf(arch: str, name: str) -> str | None:
    """包内置 launcher ELF（★M3★ shell-linux 容器编译产物，按 arch 分目录）。

    <name> 为项目应用名——CI 收录时按 app 名重命名（launcher 名 = 部署 ._pth
    命中锚，D-5：文件名即 program_name）。未收录/名称不匹配 → None（调用方
    _package_linux 硬失败拒出包，R-L19）。"""
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "_vendor", "shell-linux", arch, name)
    return p if os.path.isfile(p) else None
