"""pkapp package <platform>：平台终产物组装——windows→zip / android→apk / linux→tar.gz（M3）。

★v8.4★ 取代原 ship 成为三平台统一终产物命令；中间产物（spk）归 build，
本命令只做"壳 + spk → 交付容器"，产物统一落 <project>/release/。

windows（模式 A）：预编译壳 + spk 组装三件套到 build/ship-windows/（rcedit 可选
增强），配对自检闸门通过后打 zip（内含 <name>/ 一层目录）到 release/。
模式 A（单一发布密钥）：壳内置公钥 = 发布密钥公钥，全项目共用一个预编译壳；
每项目零编译：复制壳改名 + 放 <stem>.spk + （可选）rcedit 改图标/版本资源。
项目若误用 --keygen 项目密钥签名，通用壳验不过——出货前用壳的 --selftest-spk
做配对自检（壳内置公钥 × spk 签名），验不过不出货。

android：spk 入壳工程 assets → gradle → APK 内 spk 字节校验 → release/
（引擎 packager/apk.py；android 壳不做 spk 验签——APK 签名承担，协议 §10.2）。
"""
from __future__ import annotations

import os
import shutil
import subprocess
import zipfile

from .. import toolchain
from ..appspec import SpecError, load
from ..packager.apk import ApkError, artifact_name, build_apk


def _find_shell(explicit: str | None) -> str | None:
    """预编译壳定位：--shell / PKAPP_SHELL_EXE / 仓库内默认 build/MyApp.exe。"""
    if explicit:
        return explicit if os.path.isfile(explicit) else None
    env = os.environ.get("PKAPP_SHELL_EXE")
    if env:
        return env if os.path.isfile(env) else None
    repo = os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))))
    default = os.path.join(repo, "shell-windows", "build", "MyApp.exe")
    return default if os.path.isfile(default) else None


def _find_rcedit(explicit: str | None) -> str | None:
    """rcedit 定位：--rcedit / PKAPP_RCEDIT / 托管缓存（pkapp fetch windows）/ PATH。"""
    if explicit:
        return explicit if os.path.isfile(explicit) else None
    env = os.environ.get("PKAPP_RCEDIT")
    if env and os.path.isfile(env):
        return env
    try:
        managed = toolchain.rcedit_path()
    except toolchain.ToolchainError:      # PINS 无 rcedit pin（防御）：走 PATH 降级
        managed = ""
    if managed and os.path.isfile(managed):
        return managed
    return shutil.which("rcedit") or shutil.which("rcedit-x64")


def _shell_accepts(shell: str, spk: str) -> tuple[bool, str]:
    """壳内置公钥 × spk 签名配对自检（--selftest-spk，契约测试同款差分入口）。"""
    try:
        r = subprocess.run([shell, "--selftest-spk", spk], capture_output=True,
                           text=True, encoding="utf-8", errors="replace", timeout=60)
    except OSError as e:
        return False, f"壳自检进程启动失败: {e}"
    return r.returncode == 0, (r.stdout + r.stderr).strip()


def _rcedit_apply(rcedit: str, exe: str, icon: str | None, desc: str, version: str) -> int:
    """rcedit 改资源；单项失败即中止（资源半改状态比全不改更难排查）。"""
    steps: list[list[str]] = []
    if icon:
        steps.append(["--set-icon", icon])
    steps += [["--set-version-string", k, v] for k, v in
              (("FileDescription", desc), ("ProductName", desc),
               ("FileVersion", version), ("ProductVersion", version))]
    for s in steps:
        r = subprocess.run([rcedit, exe, *s], capture_output=True,
                           text=True, encoding="utf-8", errors="replace")
        if r.returncode != 0:
            print(f"[package] rcedit {' '.join(s[:1])} 失败: {(r.stdout + r.stderr).strip()}")
            return 1
    return 0


def cmd_package(project: str, platform: str, *, shell: str | None = None,
                shell_dir: str | None = None, variant: str = "debug",
                icon: str | None = None, desc: str | None = None,
                rcedit: str | None = None, out: str | None = None) -> int:
    try:
        spec = load(os.path.join(project, "pkapp.toml"))
    except SpecError as e:
        print(f"[package] AppSpec 错误: {e}")
        return 2
    if platform == "windows":
        return _package_windows(project, spec, shell=shell, icon=icon,
                                desc=desc, rcedit=rcedit, out=out)
    if platform == "android":
        return _package_android(project, spec, shell_dir=shell_dir,
                                variant=variant, out=out)
    print("[package] linux 终产物（tar.gz）M3 未实现")
    return 2


def _package_windows(project: str, spec, *, shell: str | None, icon: str | None,
                     desc: str | None, rcedit: str | None, out: str | None) -> int:
    name, version = spec.name, spec.version
    icon = icon or spec.platform_icon  # --icon 优先；回退 [platforms.windows].icon
    if icon and not os.path.isfile(os.path.join(project, icon) if not os.path.isabs(icon) else icon):
        print(f"[package] 图标文件不存在: {icon}（[platforms.windows].icon / --icon）")
        return 2
    if icon and not os.path.isabs(icon):
        icon = os.path.join(project, icon)

    spk = os.path.join(project, "build", "platform-windows", "runtime.spk")
    if not os.path.isfile(spk):
        print(f"[package] 未找到 spk: {spk}（先 pkapp build windows）")
        return 2
    shell_exe = _find_shell(shell)
    if not shell_exe:
        print("[package] 未找到预编译壳（模式 A）：设 PKAPP_SHELL_EXE 或 --shell <shell.exe>")
        return 2
    loader = os.path.join(os.path.dirname(shell_exe), "WebView2Loader.dll")
    if not os.path.isfile(loader):
        print(f"[package] 壳旁缺 WebView2Loader.dll: {loader}")
        return 2

    # 出货闸门：壳内置公钥必须验得过这个 spk（模式 A = 单一发布密钥）
    ok, detail = _shell_accepts(shell_exe, spk)
    if not ok:
        print("[package] 配对自检失败——通用壳验不过该 spk（壳内置公钥 ≠ 签名公钥）。\n"
              "  模式 A 项目构建须用发布密钥：PKAPP_SIGN_KEY=<发布私钥> pkapp build windows\n"
              "  （pkapp build windows --keygen 生成的是项目自带密钥，须配套重编壳，走模式 B）")
        if detail:
            print(f"  壳输出: {detail}")
        return 2

    # 组装区（中间产物）：build/ship-windows/；release/ 只放终产物 zip
    stage = os.path.join(project, "build", "ship-windows")
    os.makedirs(stage, exist_ok=True)
    exe_path = os.path.join(stage, f"{name}.exe")
    shutil.copyfile(shell_exe, exe_path)
    shutil.copyfile(spk, os.path.join(stage, f"{name}.spk"))
    shutil.copyfile(loader, os.path.join(stage, "WebView2Loader.dll"))

    rc_tool = _find_rcedit(rcedit)
    if rc_tool:
        if _rcedit_apply(rc_tool, exe_path, icon, desc or name, version) != 0:
            return 1
        print(f"[package] rcedit 资源已更新（icon={bool(icon)} desc/版本={version}）")
    else:
        print("[package] 未找到 rcedit（可选增强）：图标/版本资源未改；"
              "运行 `pkapp fetch windows` 或设 PKAPP_RCEDIT / --rcedit 后重跑")

    out_dir = os.path.abspath(out or os.path.join(project, "release"))
    os.makedirs(out_dir, exist_ok=True)
    zip_path = os.path.join(out_dir, artifact_name(name, version, "windows"))
    zip_tmp = zip_path + ".tmp"
    with zipfile.ZipFile(zip_tmp, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in (f"{name}.exe", f"{name}.spk", "WebView2Loader.dll"):
            zf.write(os.path.join(stage, f), arcname=f"{name}/{f}")
    os.replace(zip_tmp, zip_path)

    print(f"[package] {zip_path}  ({os.path.getsize(zip_path):,} B)")
    for f in (f"{name}.exe", f"{name}.spk", "WebView2Loader.dll"):
        print(f"  {name}/{f}  ({os.path.getsize(os.path.join(stage, f)):,} B)")
    print(f"[package] 组装区: {stage}（运行时身份随 exe 文件名派生：数据目录 %LOCALAPPDATA%\\{name}）")
    return 0


def _package_android(project: str, spec, *, shell_dir: str | None,
                     variant: str, out: str | None) -> int:
    spk = os.path.join(project, "build", "platform-android", "runtime.spk")
    if not os.path.isfile(spk):
        print(f"[package] 未找到 spk: {spk}（先 pkapp build android）")
        return 2
    icon = ""
    if spec.android_icon:
        icon = spec.android_icon if os.path.isabs(spec.android_icon) else os.path.join(
            os.path.abspath(project), spec.android_icon)
        if not os.path.isfile(icon):
            print(f"[package] 图标文件不存在: {spec.android_icon}（[platforms.android].icon）")
            return 2
    out_dir = os.path.abspath(out or os.path.join(project, "release"))
    # keystore 链（★v1.2★）：PKAPP_KEYSTORE env > TOML [platforms.android].keystore
    #（相对项目根）；密码/别名只走 env（PKAPP_KEYSTORE_PASS / _ALIAS），永不入 AppSpec
    keystore = os.environ.get("PKAPP_KEYSTORE") or ""
    if not keystore and spec.android_keystore:
        keystore = os.path.normpath(os.path.join(
            os.path.abspath(project), spec.android_keystore))
    keystore_pass = os.environ.get("PKAPP_KEYSTORE_PASS") or ""
    keystore_alias = os.environ.get("PKAPP_KEYSTORE_ALIAS") or "pkapp"
    try:
        apk_path = build_apk(project, spec.name, spk, shell_dir=shell_dir,
                             out_dir=out_dir, variant=variant,
                             app_id=spec.android_package,
                             version=spec.version, abis=spec.android_abis,
                             keystore=keystore, keystore_pass=keystore_pass,
                             keystore_alias=keystore_alias, icon=icon)
    except ApkError as e:
        print(f"[package] APK 组装失败: {e}")
        return 1
    print(f"[package] {apk_path}  ({os.path.getsize(apk_path):,} B)")
    print(f"[package] 变体={variant}"
          f"{'（已用 keystore 签名）' if keystore else '（debug 自动签名；release 需 keystore：TOML [platforms.android].keystore + env PKAPP_KEYSTORE_PASS）'}；"
          "android 壳不做 spk 验签——APK 签名承担（协议 §10.2）")
    return 0
