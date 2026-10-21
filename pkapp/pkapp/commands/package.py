"""pkapp package <platform>：平台终产物组装——windows→zip / android→apk / linux→tar.gz（M3）。

★v8.4★ 取代原 ship 成为三平台统一终产物命令；中间产物（spk）归 build，
本命令只做"壳 + spk → 交付容器"，产物统一落 <project>/release/。

业务编排下沉（★H2★）：windows 壳域与终产物组装 → packager/winshell.py，
android 域 → packager/apk.py（_package_android）；本模块只留 CLI 胶水
（--arch 参数校验 + AppSpec 加载 + 平台分发）。
"""
from __future__ import annotations

import os

from ..appspec import SpecError, load
from ..packager import winshell
from ..packager.apk import _package_android


def cmd_package(project: str, platform: str, *, shell: str | None = None,
                shell_dir: str | None = None, variant: str = "debug",
                icon: str | None = None, desc: str | None = None,
                rcedit: str | None = None, out: str | None = None,
                arch: str | None = None) -> int:
    if arch and platform != "android":
        print(f"[package] --arch 仅支持 android 平台（当前 {platform}）")
        return 2
    try:
        spec = load(os.path.join(project, "pkapp.toml"))
    except SpecError as e:
        print(f"[package] AppSpec 错误: {e}")
        return 2
    if platform == "windows":
        return winshell._package_windows(project, spec, shell=shell, icon=icon,
                                         desc=desc, rcedit=rcedit, out=out)
    if platform == "android":
        return _package_android(project, spec, shell_dir=shell_dir,
                                variant=variant, out=out, arch=arch)
    print("[package] linux 终产物（tar.gz）M3 未实现")
    return 2
