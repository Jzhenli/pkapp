"""组装 pkapp 内置制品目录 _vendor/（CI release 与本地同一条命令）。

输入：仓库根 shell-windows/build/MyApp.exe + WebView2Loader.dll（build.bat 产物）
      仓库根 keylib/build/pkapp_key.dll（keylib/build.bat 产物，key-holder 通用件）
      仓库根 shell-android/shell（源码壳模板，★方案A★：排除二进制/jniLibs/assets）
输出：pkapp/pkapp/_vendor/{shell,shell-android,keylib,wheels}——包内置壳 + android
      模板 + key-holder 件（locate_dll 首选回退位；package 期锚点补丁注入 K）+
      applocal 离线 wheel（applocal 不在 PyPI，build/create 的零配置入口全靠它）。

用法（仓库根）：先在 shell-windows 跑 build.bat、keylib 跑 build.bat，然后
`python pkapp/scripts/vendor.py`；pyproject 的 package-data 已收录 _vendor/**，
直接 `python -m build --wheel pkapp` 出制品。
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# android 壳模板仅收源码（gradle/kotlin/C/manifest/res）；jniLibs+stdlib.zip+build 产物
# 由构建期注入/物化再生（android_shell.py），绝不入 wheel。
# _SKIP_ANY 任意深度生效（build 产物/gradle 状态）；"tools"/build.bat 仅仓库顶层排除。
_SKIP_ANY = {"build", ".gradle", ".cxx", ".kotlin", "__pycache__"}
_ANDROID_SKIP_TOP = {"build.bat"}


def _vendor_android_shell(vroot: str) -> None:
    src = os.path.join(ROOT, "shell-android", "shell")
    dest = os.path.join(vroot, "shell-android")
    if not os.path.isdir(os.path.join(src, "app")):
        print(f"[vendor] 缺 {src}——跳过 android 壳模板（wheel 装机后 package android "
              "将报壳模板缺失）")
        return
    shutil.rmtree(dest, ignore_errors=True)
    n = 0
    for root, dirs, files in os.walk(src):
        rel = os.path.relpath(root, src)
        dirs[:] = [d for d in dirs if d not in _SKIP_ANY]
        if rel == ".":
            dirs[:] = [d for d in dirs if d != "tools"]
            files = [f for f in files if f not in _ANDROID_SKIP_TOP]
        else:
            parts = rel.split(os.sep)
            # app/src/main/{jniLibs,assets} 整树跳过（parts[3] = jniLibs/assets 自身及子孙）
            if parts[0] == "app" and len(parts) >= 4 and parts[3] in ("jniLibs", "assets"):
                dirs[:] = []
                continue
        for name in files:
            d = os.path.join(dest, rel if rel != "." else "")
            os.makedirs(d, exist_ok=True)
            shutil.copyfile(os.path.join(root, name), os.path.join(d, name))
            n += 1
    print(f"[vendor] OK: _vendor/shell-android（android 壳模板 {n} 个源码文件）")


def main() -> int:
    # CI/英区 Windows 控制台常为 cp1252——中文输出统一转 UTF-8（UnicodeEncodeError 实测踩坑）
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    shell_build = os.path.join(ROOT, "shell-windows", "build")
    exe = os.path.join(shell_build, "MyApp.exe")
    dll = os.path.join(shell_build, "WebView2Loader.dll")
    keylib_dll = os.path.join(ROOT, "keylib", "build", "pkapp_key.dll")
    for p in (exe, dll, keylib_dll):
        if not os.path.isfile(p):
            print(f"[vendor] 缺 {p}——先在 shell-windows / keylib 跑 build.bat")
            return 2

    vroot = os.path.join(ROOT, "pkapp", "pkapp", "_vendor")
    shell_dir = os.path.join(vroot, "shell")
    keylib_dir = os.path.join(vroot, "keylib", "windows")
    wheels_dir = os.path.join(vroot, "wheels")
    shutil.rmtree(wheels_dir, ignore_errors=True)   # 防旧版本 wheel 滞留
    os.makedirs(shell_dir, exist_ok=True)
    os.makedirs(keylib_dir, exist_ok=True)
    os.makedirs(wheels_dir, exist_ok=True)
    shutil.copyfile(exe, os.path.join(shell_dir, "MyApp.exe"))
    shutil.copyfile(dll, os.path.join(shell_dir, "WebView2Loader.dll"))
    shutil.copyfile(keylib_dll, os.path.join(keylib_dir, "pkapp_key.dll"))
    # android key-holder（可选件，build_android.bat 产物，需 NDK）——缺失不阻塞
    # vendor（明文包与 windows 加密包不依赖）；加密 android 包依赖它
    keylib_so = os.path.join(ROOT, "keylib", "build", "lib_pkapp_key.so")
    if os.path.isfile(keylib_so):
        akeylib_dir = os.path.join(vroot, "keylib", "android")
        os.makedirs(akeylib_dir, exist_ok=True)
        shutil.copyfile(keylib_so, os.path.join(akeylib_dir, "lib_pkapp_key.so"))
    else:
        print("[vendor] 跳过 _vendor/keylib/android（无 lib_pkapp_key.so——"
              "加密 android 包需先 keylib 跑 build_android.bat，需 NDK）")
    _vendor_android_shell(vroot)

    r = subprocess.run([sys.executable, "-m", "pip", "wheel", "--no-deps", "-q",
                        "-w", wheels_dir, os.path.join(ROOT, "applocal")])
    if r.returncode != 0:
        print("[vendor] applocal wheel 构建失败")
        return 1
    n = len([f for f in os.listdir(wheels_dir) if f.endswith(".whl")])
    print(f"[vendor] OK: _vendor/shell（MyApp.exe + WebView2Loader.dll）"
          f"+ _vendor/keylib/windows（key-holder 通用件）"
          f"{'+ _vendor/keylib/android ' if os.path.isfile(keylib_so) else ''}"
          f"+ _vendor/wheels（{n} wheel）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
