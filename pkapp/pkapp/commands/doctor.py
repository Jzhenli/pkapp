"""pkapp doctor：环境诊断——runtime 快照（B.t 断言）/ WebView2 / JDK/SDK / applocal 版本区间。"""
from __future__ import annotations

import glob
import os
import subprocess
import sys

from ..appspec import SpecError, load
from ..packager import runtime as rtmod


def _check_webview2() -> str:
    """WebView2 Evergreen 存在性（方案 §5.5：缺失 → 提示随包 Standalone Installer 或 Fixed Version）。"""
    if sys.platform != "win32":
        return "skip（非 Windows 宿主）"
    try:
        import winreg
    except ImportError:
        return "unknown"
    keys = [
        r"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}",
        r"SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}",
    ]
    for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
        for path in keys:
            try:
                with winreg.OpenKey(hive, path) as k:
                    pv, _ = winreg.QueryValueEx(k, "pv")
                    if pv and pv != "0.0.0.0":
                        return f"ok（Evergreen {pv}）"
            except OSError:
                continue
    return "missing——离线机请随包分发 Standalone Installer 或改 Fixed Version 模式（方案 §5.5）"


def _venv_applocal_version(project: str) -> str:
    sub = "Scripts/python.exe" if os.name == "nt" else "bin/python"
    py = os.path.join(project, ".venv", sub)
    if not os.path.isfile(py):
        return "missing（项目无 .venv）"
    r = subprocess.run([py, "-c",
                        "import importlib.metadata as m; print(m.version('applocal'))"],
                       capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else f"missing（{r.stderr.strip()[:80]}）"


def cmd_doctor(project: str) -> int:
    problems = 0
    print(f"[doctor] pkapp {__import__('pkapp').__version__} / python {sys.version.split()[0]}")

    # AppSpec + applocal 版本区间
    spec = None
    try:
        spec = load(os.path.join(project, "pkapp.toml"))
        al = _venv_applocal_version(project)
        ok = al and not al.startswith("missing")
        if ok:
            from ..appspec import _ver_tuple
            ok = _ver_tuple(al) >= _ver_tuple("0.1.0")
        print(f"[doctor] applocal in .venv: {al}（契约层，区间下限随 AppSpec 升级）")
        if not ok:
            problems += 1
    except SpecError as e:
        print(f"[doctor] AppSpec: {e}")
        problems += 1

    # runtime 快照（B.t① 共享构建 + B.t② 安装目录洁净对项目目录的投影）
    if spec is not None:
        try:
            snap = rtmod.resolve(spec, "windows")
            print(f"[doctor] runtime.windows: {snap.python_version} @ {snap.dir} "
                  f"(python_dll={snap.python_dll})")
            stray = glob.glob(os.path.join(project, "*._pth"))
            if stray:
                print(f"[doctor] B.t② 项目/安装目录出现 _pth: {stray}")
                problems += 1
        except rtmod.RuntimeResolveError as e:
            print(f"[doctor] runtime.windows: {e}")
        _check_android(spec)
    else:
        print("[doctor] runtime.android: skip（AppSpec 加载失败）")

    # 平台周边
    print(f"[doctor] WebView2: {_check_webview2()}")
    print(f"[doctor] JAVA_HOME: {'set' if os.environ.get('JAVA_HOME') else 'unset（M2 Android 才需要）'}")
    print(f"[doctor] ANDROID_SDK_ROOT: "
          f"{'set' if os.environ.get('ANDROID_SDK_ROOT') else 'unset（M2 Android 才需要）'}")
    print(f"[doctor] 私钥: "
          f"{'found' if (os.environ.get('PKAPP_SIGN_KEY') or os.path.isfile(os.path.join(project, '.pkapp', 'sign.key'))) else 'missing（build 前先 pkapp build --keygen 或设 PKAPP_SIGN_KEY）'}")
    return 1 if problems else 0


def _check_android(spec) -> None:
    """android 工具链逐项在位检查（PKAPP_ANDROID_TOOLCHAIN 整体根 > 托管缓存），缺失打精确 fetch 命令。"""
    from .. import toolchain

    tc = os.environ.get("PKAPP_ANDROID_TOOLCHAIN")
    if tc:
        # 旧整体根语义（<root>/{jdk/jdk-17.0.20.1+1, android-sdk, gradle-8.9, gradle-home}）
        paths = {
            "JAVA_HOME": os.path.join(tc, "jdk", "jdk-17.0.20.1+1"),
            "gradle": os.path.join(tc, "gradle-8.9", "bin",
                                   "gradle.bat" if os.name == "nt" else "gradle"),
            "ANDROID_HOME": os.path.join(tc, "android-sdk"),
        }
    else:
        ap = toolchain.android_paths()
        paths = {"JAVA_HOME": ap["java_home"], "gradle": ap["gradle"],
                 "ANDROID_HOME": ap["android_home"]}
        if not os.path.isfile(paths["gradle"]):
            print(f"[doctor] android 工具链缺失——运行 `pkapp fetch android`"
                  f"（或设 PKAPP_ANDROID_TOOLCHAIN 指向手工布置的整体根）")
            print(f"[doctor] runtime.android: skip（工具链未就位）")
            return
    missing = []
    for name, p in paths.items():
        ok = os.path.isfile(p) if name == "gradle" else os.path.isdir(p)
        print(f"[doctor] android {name}: {'ok' if ok else f'missing（{p}）'}")
        if not ok:
            missing.append(name)
    if missing:
        print("[doctor] android 工具链缺失——运行 `pkapp fetch android`")
    # android 运行时快照（两 abi 布局断言）
    try:
        snap = rtmod.resolve(spec, "android", abis=getattr(spec, "android_abis", ("arm64-v8a",)))
        print(f"[doctor] runtime.android: {snap.python_version} @ {snap.dir} "
              f"(abis={','.join(snap.abis)})")
    except rtmod.RuntimeResolveError as e:
        print(f"[doctor] runtime.android: {e}")
