"""key-holder 现场定制编译（★档位1 K 派生化，PROTECTION_ROADMAP §3.1/§3.3★）。

构建/打包期：resolve K_app → generate_kdata_c 现场生成专属 kdata.c → 与 key.c
同编出本包专属 keylib 件（非二进制 patch）——件内不再有锚点常量，横向通吃模型
（提一次 K/逆向一次手法破所有包）被压制为"每包一破"。

编译矩阵（§3.3 运维面）：windows=MSVC（vswhere 定位 vcvars64）、
android=NDK clang（ANDROID_NDK_HOME > 托管 SDK > 标准 SDK 位）、linux=cc/gcc。
编译不可得 → 预制件锚点补丁退化路径（locate_dll + patch_dll，保护面明示降级——
件内保留锚点标记；预制件分发模式据此"退化为 fallback"，§3.3）。

keylib 源码（key.c/key.h）定位序：env PKAPP_KEYLIB_SRC > 仓库 keylib/src（源码
形态开发）> _vendor/keylib/src（wheel 形态，scripts/vendor.py 收录）。
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile

from .keylib import KeyLibError, generate_kdata_c, locate_dll, patch_dll

# linux 目标（PRETECTION_ROADMAP §3.3 三平台矩阵）；windows/android 走专属定位
_COMPILE_FLAGS = ["-O2", "-shared", "-fPIC", "-std=c17"]


def keylib_source_dir() -> str | None:
    """keylib C 源码目录（key.c + key.h + kdata.c 模板不在此——kdata.c 恒现场生成）。"""
    env = os.environ.get("PKAPP_KEYLIB_SRC")
    if env and os.path.isfile(os.path.join(env, "key.c")):
        return env
    here = os.path.dirname(os.path.abspath(__file__))
    # 源码仓库形态：pkapp/pkapp/packager/ → 仓库根/keylib/src（向上 3 级）
    repo = os.path.join(os.path.dirname(os.path.dirname(
        os.path.dirname(here))), "keylib", "src")
    if os.path.isfile(os.path.join(repo, "key.c")):
        return repo
    # wheel 形态：<site-packages>/pkapp/_vendor/keylib/src（scripts/vendor.py 收录）
    # here 已是目录（packager）——dirname 一次到包根 pkapp，与 locate_dll 算法对齐
    # （两层 dirname 会错位到 <site-packages>/_vendor，wheel 形态恒找不到 → 静默降级）
    vendored = os.path.join(os.path.dirname(here), "_vendor", "keylib", "src")
    if os.path.isfile(os.path.join(vendored, "key.c")):
        return vendored
    return None


def _run(cmd, cwd: str) -> None:
    """执行编译命令。list 形态直传；str 形态经 cmd /c（vcvars 脚本含引号路径
    与 && 链——列表形态 subprocess 会把内嵌引号转义成 \\" 而 cmd 不认，故字符串
    整体直传 CreateProcess）。"""
    label = cmd[:40] if isinstance(cmd, str) else " ".join(cmd[:2])
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                       errors="replace")
    if r.returncode != 0:
        raise KeyLibError(
            f"keylib 编译失败（{label}…）:\n"
            f"{(r.stdout + r.stderr)[-2000:]}")


def _find_vcvars64() -> str | None:
    base = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    vswhere = os.path.join(base, "Microsoft Visual Studio", "Installer",
                           "vswhere.exe")
    if not os.path.isfile(vswhere):
        return None
    r = subprocess.run([vswhere, "-latest", "-products", "*", "-requires",
                        "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                        "-property", "installationPath"],
                       capture_output=True, text=True, errors="replace")
    vsdir = r.stdout.strip().splitlines()[-1].strip() if r.stdout.strip() else ""
    if not vsdir:
        return None
    vcvars = os.path.join(vsdir, "VC", "Auxiliary", "Build", "vcvars64.bat")
    return vcvars if os.path.isfile(vcvars) else None


def _compile_windows(src_dir: str, work: str, out_path: str) -> None:
    vcvars = _find_vcvars64()
    if not vcvars:
        raise KeyLibError("MSVC 未就位（vswhere 找不到 VC.Tools.x86.x64）——"
                          "安装 VS2022 BuildTools C++ 工具集后重试")
    # vcvars 在子 cmd 内加载环境再 cl（build.bat 同式）；字符串直传 cmd /c，
    # 引号路径 + && 重定向链由 cmd 自身解析（list 形态会被 subprocess 错误转义）。
    # cwd=work 且 kdata.c 在 work → .obj 默认落 cwd（/Fo 目录形态与多源文件冲突 D8036）
    script = (f'call "{vcvars}" x64 >nul && '
              f'cl /nologo /W4 /O2 /MT /utf-8 /std:c17 /LD '
              f'"{os.path.join(src_dir, "key.c")}" kdata.c '
              f'/Fe:"{out_path}"')
    _run(f"cmd /c {script}", cwd=work)


def _find_ndk() -> str | None:
    env = os.environ.get("ANDROID_NDK_HOME")
    if env and os.path.isdir(env):
        return env
    candidates = []
    try:
        from ..toolchain import android_paths
        candidates.append(os.path.join(android_paths()["android_home"], "ndk"))
    except Exception:
        pass
    la = os.environ.get("LOCALAPPDATA")
    if la:
        candidates.append(os.path.join(la, "Android", "Sdk", "ndk"))
    for ndkroot in candidates:
        if os.path.isdir(ndkroot):
            vers = sorted((d for d in os.listdir(ndkroot)
                           if re.fullmatch(r"\d+\.\d+\.\d+", d)),
                          key=lambda v: [int(x) for x in v.split(".")])
            if vers:
                return os.path.join(ndkroot, vers[-1])
    return None


def _compile_android(src_dir: str, work: str, out_path: str, abi: str) -> None:
    ndk = _find_ndk()
    if not ndk:
        raise KeyLibError("NDK 未就位（ANDROID_NDK_HOME / 托管 SDK / 标准 SDK 位）——"
                          "先 `pkapp fetch android` 或设 ANDROID_NDK_HOME")
    host = "windows-x86_64" if os.name == "nt" else "linux-x86_64"
    cc = os.path.join(ndk, "toolchains", "llvm", "prebuilt", host, "bin",
                      "clang.exe" if os.name == "nt" else "clang")
    if not os.path.isfile(cc):
        raise KeyLibError(f"NDK clang 缺失: {cc}")
    triple = {"arm64-v8a": "aarch64-linux-android24",
              "armeabi-v7a": "armv7a-linux-androideabi24",
              "x86_64": "x86_64-linux-android24",
              "x86": "i686-linux-android24"}.get(abi)
    if not triple:
        raise KeyLibError(f"不支持的 ABI: {abi}")
    _run([cc, f"-target", triple, *_COMPILE_FLAGS, "-Wall", "-Wextra", "-Werror",
          os.path.join(src_dir, "key.c"), "kdata.c", "-o", out_path], cwd=work)


def _compile_linux(src_dir: str, work: str, out_path: str) -> None:
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if not cc:
        raise KeyLibError("linux 编译器缺失（cc/gcc/clang 均不可得）")
    _run([cc, *_COMPILE_FLAGS, os.path.join(src_dir, "key.c"), "kdata.c",
          "-o", out_path], cwd=work)


def compile_keylib(platform: str, k_app: bytes, out_path: str, *,
                   abi: str = "arm64-v8a") -> None:
    """现场定制编译：临时目录生成 kdata.c(K_app) → 平台编译器同编 key.c。

    产物 = 本包专属 keylib 件（K_app 编译期烧入，无锚点常量）。失败抛
    KeyLibError（调用方决定退化路径）。
    """
    src_dir = keylib_source_dir()
    if not src_dir:
        raise KeyLibError(
            "keylib C 源码缺失（keylib/src/key.c）——wheel 形态请重跑 "
            "pkapp/scripts/vendor.py（收录 _vendor/keylib/src）或设 PKAPP_KEYLIB_SRC")
    work = tempfile.mkdtemp(prefix="pkapp-keybuild-")
    os.makedirs(os.path.dirname(os.path.abspath(out_path)) or ".", exist_ok=True)
    try:
        with open(os.path.join(work, "kdata.c"), "w", encoding="utf-8") as f:
            f.write(generate_kdata_c(k_app))
        if platform == "windows":
            _compile_windows(src_dir, work, os.path.abspath(out_path))
        elif platform == "android":
            _compile_android(src_dir, work, os.path.abspath(out_path), abi)
        elif platform == "linux":
            _compile_linux(src_dir, work, os.path.abspath(out_path))
        else:
            raise KeyLibError(f"未知平台: {platform}")
    finally:
        shutil.rmtree(work, ignore_errors=True)
    if not os.path.isfile(out_path):
        raise KeyLibError(f"keylib 编译无产物: {out_path}")


def produce_keylib(platform: str, k_app: bytes, out_path: str, *,
                   abi: str = "arm64-v8a") -> str:
    """本包专属 keylib 件产出（编译优先、锚点补丁退化），返回方式说明。

    - "compiled"：现场定制编译（首选，件内无锚点常量）；
    - "fallback"：预制通用件 + 锚点补丁（编译器不可得时的退化路径，保护面
      明示降级——§3.3"预制件分发模式退化为 fallback"）。
    两条路径产物 key_id 同为 SHA256(K_app)[:16] hex——闸门语义零差异。
    """
    try:
        compile_keylib(platform, k_app, out_path, abi=abi)
        return "compiled"
    except KeyLibError as e:
        reason = str(e).splitlines()[0]
    prefab = locate_dll(platform)
    if not prefab:
        raise KeyLibError(
            f"keylib 现场编译不可得且预制件缺失（{reason}）——"
            "安装平台工具链或补齐 keylib 件后重试")
    patch_dll(prefab, out_path, k_app)
    print(f"[keylib] 现场编译退化锚点补丁路径（{reason}）——件内保留锚点标记，"
          "保护面降级；建议补齐平台编译工具链")
    return "fallback"
