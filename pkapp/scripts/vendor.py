"""组装 pkapp 内置制品目录 _vendor/（CI release 与本地同一条命令）。

输入：仓库根 shell-windows/build/MyApp.exe + WebView2Loader.dll（build.bat 产物）
      仓库根 shell-linux/build/{myapp,aarch64/myapp,armv7l/myapp}（launcher ELF ×3：
      x86_64 = build.sh 本地产物；arm 双线 = CI launcher job artifact 落位子目录）
      仓库根 keylib/build/pkapp_key.dll（keylib/build.bat 产物，key-holder 通用件）
      仓库根 shell-android/shell（源码壳模板，★方案A★：排除二进制/jniLibs/assets）
输出：pkapp/pkapp/_vendor/{shell,shell-linux/<arch>,keylib,wheels}——包内置壳 +
      linux launcher ELF（按 arch 分目录，package linux --arch 的壳源）+ android
      模板 + key-holder 件（locate_dll 首选回退位；package 期锚点补丁注入 K）+
      applocal 离线 wheel（applocal 不在 PyPI，build/create 的零配置入口全靠它）。

android keylib 预编译件不收录（★H4 fail-fast 2026-10★）：单槽 so 无 ABI 语义
（build_android.bat 产物可能是任一 ABI），锚点补丁退化路径会把它补进任意 ABI 的
APK——key_id 配对正确但目标机 dlopen 即崩。且能执行 android 打包命令的机器必已
装 NDK（fetch android 必含 NDK 27），现场定制编译是唯一默认路径；模式 B 自管件
经 PKAPP_KEYLIB 显式指定（见 keybuild.produce_keylib / keylib.locate_dll）。

收录矩阵（每条目一行 OK/SKIP+原因，消灭静默跳过）+ --require 闸门：要求的条目
非 OK → 非零退出。release.yml 以全量 require 表达"发布件完整性"意图；本地开发
可省略（宽松形态，缺件仅 SKIP）。

用法（仓库根）：先在 shell-windows 跑 build.bat、keylib 跑 build.bat，然后
`python pkapp/scripts/vendor.py [--require 条目[,条目…]]`；pyproject 的
package-data 已收录 _vendor/**，直接 `python -m build --wheel pkapp` 出制品。
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from functools import partial

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# android 壳模板仅收源码（gradle/kotlin/C/manifest/res）；jniLibs+stdlib.zip+build 产物
# 由构建期注入/物化再生（android_shell.py），绝不入 wheel。
# _SKIP_ANY 任意深度生效（build 产物/gradle 状态）；"tools"/build.bat 仅仓库顶层排除。
_SKIP_ANY = {"build", ".gradle", ".cxx", ".kotlin", "__pycache__"}
_ANDROID_SKIP_TOP = {"build.bat"}

# 收录条目注册表（条目名 → 描述）。
# 硬闸门条目（shell-windows/keylib-windows/applocal-wheel）缺件直接非零退出，
# 与 --require 无关（发布件的最小完整面）；可选条目缺件记 SKIP，仅 --require
# 命中时升级为失败。
ENTRIES: dict[str, str] = {
    "shell-windows": "包内置壳（MyApp.exe + WebView2Loader.dll）",
    "shell-linux-x86_64": "launcher ELF x86_64（_vendor/shell-linux/x86_64/myapp，manylinux2014 容器编译）",
    "shell-linux-aarch64": "launcher ELF aarch64（_vendor/shell-linux/aarch64/myapp，arm runner 容器编译，阶段 5）",
    "shell-linux-armv7l": "launcher ELF armv7l（_vendor/shell-linux/armv7l/myapp，ubuntu:20.04 交叉编译，阶段 5）",
    "keylib-windows": "key-holder 通用件（pkapp_key.dll，锚点补丁退化位）",
    "keylib-src": "keylib C 源码（key.c/key.h，wheel 形态现场编译供给）",
    "shell-android": "android 壳模板（源码形态）",
    "applocal-wheel": "applocal 离线 wheel（非 PyPI 私有件）",
}
_HARD_ENTRIES = ("shell-windows", "keylib-windows", "applocal-wheel")


def _vendor_shell_windows(vroot: str, root: str) -> tuple[str, str]:
    """包内置壳收录（零编译壳：wheel 装机后 package windows 的唯一壳源）。"""
    build = os.path.join(root, "shell-windows", "build")
    missing = [p for p in (os.path.join(build, "MyApp.exe"),
                           os.path.join(build, "WebView2Loader.dll"))
               if not os.path.isfile(p)]
    if missing:
        # SKIP 即清旧产物：滞留件会照常进 wheel（静默陈旧），矩阵不可只是展示层
        shutil.rmtree(os.path.join(vroot, "shell"), ignore_errors=True)
        return "SKIP", f"缺 {'; '.join(missing)}——先在 shell-windows 跑 build.bat"
    dest = os.path.join(vroot, "shell")
    os.makedirs(dest, exist_ok=True)
    for fn in ("MyApp.exe", "WebView2Loader.dll"):
        shutil.copyfile(os.path.join(build, fn), os.path.join(dest, fn))
    return "OK", "_vendor/shell（MyApp.exe + WebView2Loader.dll）"


# launcher ELF 源位（arch → shell-linux/build/ 下相对路径）。x86_64 = build 根
# （build.sh 本地产物 + CI artifact 直落位）；arm 双线 = build/<arch>/ 子目录
#（CI artifact 落位，★M3 阶段 5 前置★：release.yml launcher job ×3）。
_LINUX_ARCH_SOURCES: dict[str, tuple[str, ...]] = {
    "x86_64": ("myapp",),
    "aarch64": ("aarch64", "myapp"),
    "armv7l": ("armv7l", "myapp"),
}


def _vendor_shell_linux_arch(vroot: str, root: str, arch: str) -> tuple[str, str]:
    """launcher ELF 按 arch 收录（★M3 阶段 5 前置★：_vendor/shell-linux/<arch>/myapp，
    wheel 装机后 package linux --arch <arch> 的壳源，消费端 launcher_elf(arch, name)）。

    编译口径：x86_64/aarch64 = manylinux2014（glibc 2.17 地板，aarch64 走 arm
    runner 原生容器）；armv7l = ubuntu:20.04 交叉链（sysroot glibc 2.31 与板子
    对齐——manylinux2014 不提供 armhf 交叉链，D-2 两条并行基线勿混读）+ QEMU
    user 模式 --selftest 关闸（release.yml launcher job ×3）。
    SKIP 即清本 arch 子树（滞留件照常进 wheel = 静默陈旧变体，H4 同款）。"""
    src = os.path.join(root, "shell-linux", "build", *_LINUX_ARCH_SOURCES[arch])
    dest = os.path.join(vroot, "shell-linux", arch)
    if not os.path.isfile(src):
        shutil.rmtree(dest, ignore_errors=True)           # SKIP 即清旧产物（本 arch 子树）
        return "SKIP", (f"缺 {src}——launcher ELF（CI launcher job artifact / "
                        "本地 shell-linux/build.sh）")
    os.makedirs(dest, exist_ok=True)
    shutil.copyfile(src, os.path.join(dest, "myapp"))
    return "OK", f"_vendor/shell-linux/{arch}（launcher ELF，录名 myapp）"


def _vendor_keylib_windows(vroot: str, root: str) -> tuple[str, str]:
    """windows key-holder 通用件收录（keybuild 退化路径 locate_dll 的首选回退位）。"""
    src = os.path.join(root, "keylib", "build", "pkapp_key.dll")
    if not os.path.isfile(src):
        shutil.rmtree(os.path.join(vroot, "keylib", "windows"),
                      ignore_errors=True)              # SKIP 即清旧产物（同上）
        return "SKIP", f"缺 {src}——先在 keylib 跑 build.bat"
    dest = os.path.join(vroot, "keylib", "windows")
    os.makedirs(dest, exist_ok=True)
    shutil.copyfile(src, os.path.join(dest, "pkapp_key.dll"))
    return "OK", "_vendor/keylib/windows（key-holder 通用件）"


def _vendor_keylib_src(vroot: str, root: str) -> tuple[str, str]:
    """keylib C 源码收录（★档位1 §3.3★：现场定制编译的 wheel 形态供给——
    keybuild.keylib_source_dir() 的 _vendor 回退位；kdata.c 恒现场生成不入 vendor）。
    缺失仅影响 wheel 形态的现场编译（退化路径随之不可用），故为可选条目。"""
    src_dir = os.path.join(root, "keylib", "src")
    missing = [fn for fn in ("key.c", "key.h")
               if not os.path.isfile(os.path.join(src_dir, fn))]
    if missing:
        shutil.rmtree(os.path.join(vroot, "keylib", "src"),
                      ignore_errors=True)              # SKIP 即清旧产物（同上）
        return "SKIP", f"缺 {src_dir} 下 {'/'.join(missing)}——现场编译供给断供"
    dest = os.path.join(vroot, "keylib", "src")
    os.makedirs(dest, exist_ok=True)
    for fn in ("key.c", "key.h"):
        shutil.copyfile(os.path.join(src_dir, fn), os.path.join(dest, fn))
    return "OK", "_vendor/keylib/src（现场定制编译源）"


def _vendor_android_shell(vroot: str, root: str) -> tuple[str, str]:
    """android 壳模板收录（源码形态；缺失时 wheel 装机后 package android 将报
    壳模板缺失——构建期注入/物化再生的原料断供）。"""
    src = os.path.join(root, "shell-android", "shell")
    dest = os.path.join(vroot, "shell-android")
    if not os.path.isdir(os.path.join(src, "app")):
        shutil.rmtree(dest, ignore_errors=True)        # SKIP 即清旧产物（同上）
        return "SKIP", f"缺 {src}——android 壳模板（wheel 装机后 package android 受阻）"
    shutil.rmtree(dest, ignore_errors=True)
    n = 0
    for cur, dirs, files in os.walk(src):
        rel = os.path.relpath(cur, src)
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
            shutil.copyfile(os.path.join(cur, name), os.path.join(d, name))
            n += 1
    return "OK", f"_vendor/shell-android（android 壳模板 {n} 个源码文件）"


def _build_applocal_wheel(vroot: str, root: str) -> tuple[str, str]:
    """applocal 离线 wheel 构建（applocal 不在 PyPI——build/create 零配置入口全靠它）。"""
    wheels_dir = os.path.join(vroot, "wheels")
    shutil.rmtree(wheels_dir, ignore_errors=True)   # 防旧版本 wheel 滞留进 pkapp wheel
    os.makedirs(wheels_dir, exist_ok=True)
    r = subprocess.run([sys.executable, "-m", "pip", "wheel", "--no-deps", "-q",
                        "-w", wheels_dir, os.path.join(root, "applocal")])
    if r.returncode != 0:
        return "SKIP", "applocal wheel 构建失败"
    n = len([f for f in os.listdir(wheels_dir) if f.endswith(".whl")])
    return "OK", f"_vendor/wheels（{n} wheel）"


def run(argv: list[str] | None = None, root: str = ROOT) -> int:
    """收录主流程（root 参数化便于测试注入假仓库树）。"""
    # CI/英区 Windows 控制台常为 cp1252——中文输出统一转 UTF-8（UnicodeEncodeError
    # 实测踩坑）。必须在 argparse 之前：--require 传错参数时 usage 含中文 help 文本
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

    ap = argparse.ArgumentParser(description="组装 pkapp 包内置制品 _vendor/")
    ap.add_argument("--require", default="", metavar="条目[,条目…]",
                    help=f"要求这些条目收录成功（合法值: {', '.join(ENTRIES)}）；"
                         "release.yml 全量 require，本地可省略")
    args = ap.parse_args(argv)
    requires = [s.strip() for s in args.require.split(",") if s.strip()]
    unknown = [name for name in requires if name not in ENTRIES]
    if unknown:
        print(f"[vendor] --require 未知条目: {', '.join(unknown)}——"
              f"合法值: {', '.join(ENTRIES)}")
        return 2

    vroot = os.path.join(root, "pkapp", "pkapp", "_vendor")
    os.makedirs(vroot, exist_ok=True)
    results: dict[str, tuple[str, str]] = {}
    hard_rc: dict[str, int] = {}
    for name, fn in (("shell-windows", _vendor_shell_windows),
                     ("shell-linux-x86_64",
                      partial(_vendor_shell_linux_arch, arch="x86_64")),
                     ("shell-linux-aarch64",
                      partial(_vendor_shell_linux_arch, arch="aarch64")),
                     ("shell-linux-armv7l",
                      partial(_vendor_shell_linux_arch, arch="armv7l")),
                     ("keylib-windows", _vendor_keylib_windows),
                     ("keylib-src", _vendor_keylib_src),
                     ("shell-android", _vendor_android_shell),
                     ("applocal-wheel", _build_applocal_wheel)):
        status, detail = fn(vroot, root)
        results[name] = (status, detail)
        print(f"[vendor] {status}: {name} — {detail}")
        if status != "OK" and name in _HARD_ENTRIES:
            # 最小完整面缺件：与 --require 无关的硬闸门（发布件不完整即拒收）
            hard_rc[name] = 2 if name != "applocal-wheel" else 1
    if hard_rc:
        return max(hard_rc.values())

    gaps = [name for name in requires if results[name][0] != "OK"]
    if gaps:
        print("[vendor] --require 缺件（收录矩阵见上）:")
        for name in gaps:
            print(f"[vendor]   {name}: {results[name][0]} — {results[name][1]}")
        return 2
    return 0


def main() -> int:
    return run()


if __name__ == "__main__":
    sys.exit(main())
