"""APK 组装引擎（★v8.4★，pkapp package android 的实现）：spk 入壳 assets → gradle → 验收落 release/。

壳工程（gradle）与安卓工具链是构建机环境，路径解析顺序：显式参数 > 环境变量
（PKAPP_SHELL_DIR / PKAPP_ANDROID_TOOLCHAIN）> toolchain 默认布局。

资产增量陷阱（真机踩坑沉淀）：拷贝保留源文件 mtime，构建后拷入的 assets 可能被
增量 mergeDebugAssets 漏掉——拷入后必须 touch assets 目录，且组装完成后以
"APK 内 assets/runtime.spk 与源 spk 字节一致"作硬校验，漏掉即报错而非真机白屏。
"""
from __future__ import annotations

import os
import shutil
import zipfile

DEFAULT_TOOLCHAIN = r"D:\code\pack\toolchain"

# 壳工程随仓库分发，默认取仓库内 shell-android/shell（apk.py 位于 <repo>/pkapp/pkapp/packager/）
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))))
DEFAULT_SHELL_DIR = os.path.join(_REPO_ROOT, "shell-android", "shell")


class ApkError(RuntimeError):
    """APK 组装失败（壳工程缺失 / gradle 失败 / 资产未入包）。"""


def build_apk(project: str, app_name: str, spk_path: str, *,
              shell_dir: str | None = None, out_dir: str | None = None,
              variant: str = "debug") -> str:
    """spk → 壳 assets → gradle → <project>/release/<app_name>.apk。

    返回 APK 路径；任何一步失败抛 ApkError（gradle 输出尾部随异常给出）。
    """
    shell = shell_dir or os.environ.get("PKAPP_SHELL_DIR") or DEFAULT_SHELL_DIR
    assets = os.path.join(shell, "app", "src", "main", "assets")
    gradle_py = os.path.join(shell, "build.gradle.kts")
    if not os.path.isdir(assets) or not os.path.isfile(gradle_py):
        raise ApkError(f"壳工程不完整（缺 {assets} 或 {gradle_py}）；"
                       "可用 --shell-dir 或 PKAPP_SHELL_DIR 指定壳工程根")

    with open(spk_path, "rb") as f:
        spk_bytes = f.read()
    # 拷入 + touch 目录（绕过增量 mergeDebugAssets 的 mtime 盲区）
    os.makedirs(assets, exist_ok=True)
    with open(os.path.join(assets, "runtime.spk"), "wb") as f:
        f.write(spk_bytes)
    os.utime(assets, None)

    _run_gradle(shell, variant)

    apk_src = os.path.join(shell, "app", "build", "outputs", "apk", variant,
                           f"app-{variant}.apk")
    if not os.path.isfile(apk_src):
        raise ApkError(f"gradle 未产出 {apk_src}")
    _verify_asset_in_apk(apk_src, spk_bytes)

    dest_dir = out_dir or os.path.join(project, "release")
    os.makedirs(dest_dir, exist_ok=True)
    dest = os.path.join(dest_dir, f"{app_name}.apk")
    shutil.copyfile(apk_src, dest)
    return dest


def _run_gradle(shell: str, variant: str) -> None:
    """转发 gradle assemble<Variant>；工具链路径 = env > 默认 toolchain 布局。"""
    import subprocess

    tc = os.environ.get("PKAPP_ANDROID_TOOLCHAIN") or DEFAULT_TOOLCHAIN
    env = dict(os.environ)
    env.setdefault("JAVA_HOME", os.path.join(tc, "jdk", "jdk-17.0.20.1+1"))
    env.setdefault("ANDROID_HOME", os.path.join(tc, "android-sdk"))
    env.setdefault("GRADLE_USER_HOME", os.path.join(tc, "gradle-home"))
    gradle = os.path.join(tc, "gradle-8.9", "bin",
                          "gradle.bat" if os.name == "nt" else "gradle")
    if not os.path.isfile(gradle):
        raise ApkError(f"gradle 不存在: {gradle}（设 PKAPP_ANDROID_TOOLCHAIN 或 PATH）")
    r = subprocess.run([gradle, "--no-daemon", "-p", shell,
                        f"assemble{variant.capitalize()}"],
                       env=env, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=900)
    if r.returncode != 0:
        tail = "\n".join((r.stdout or "").splitlines()[-15:])
        raise ApkError(f"gradle 失败（exit {r.returncode}）:\n{tail}")


def _verify_asset_in_apk(apk_path: str, spk_bytes: bytes) -> None:
    """硬校验：APK 内 assets/runtime.spk 必须与源 spk 字节一致（增量漏拷 = 构建失败）。"""
    with zipfile.ZipFile(apk_path) as zf:
        names = set(zf.namelist())
        if "assets/runtime.spk" not in names:
            raise ApkError("assets/runtime.spk 未入 APK（增量 mergeDebugAssets 漏拷？"
                           "重跑一次或 clean 后重试）")
        if zf.read("assets/runtime.spk") != spk_bytes:
            raise ApkError("APK 内 runtime.spk 与源 spk 字节不一致（陈旧资产？）")
