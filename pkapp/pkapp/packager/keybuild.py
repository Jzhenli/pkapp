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

from .keylib import (KeyLib, KeyLibError, derive_k_app, generate_kdata_c,
                     key_id_hex, locate_dll, patch_dll, resolve_master_key)

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

    ★android/linux 例外（H4 fail-fast 2026-10；linux 同款 M3 条 4）★：无
    fallback——单槽预制件无 ABI/arch 语义，锚点补丁会把错 ABI/arch 件打进包
    （key_id 配对正确、目标机加载即崩）。linux 现场编译需目标工具链（交叉编译
    或同架构 linux host——WSL2/CI），不可得 → KeyLibError 指路；自管件（模式 B）
    经 PKAPP_KEYLIB 显式指定，由调用方（_stage_keylib）处理。
    """
    try:
        compile_keylib(platform, k_app, out_path, abi=abi)
        return "compiled"
    except KeyLibError as e:
        reason = str(e).splitlines()[0]
    if platform == "android":
        raise KeyLibError(
            f"android keylib 现场编译不可得（{reason}）——NDK 是 android 打包的"
            "必需工具链（pkapp fetch android 或设 ANDROID_NDK_HOME）。android 无"
            "预制件退化路径（单槽 so 会把错 ABI 件打进 APK）；自管件请设 "
            "PKAPP_KEYLIB 显式指定")
    if platform == "linux":
        raise KeyLibError(
            f"linux keylib 现场编译不可得（{reason}）——加密态构建需 linux 工具链"
            "（WSL2：wsl 内重跑，或 CI ubuntu job）。linux 无预制件退化路径"
            "（单槽 so 会把错 arch 件打进包）；自管件请设 PKAPP_KEYLIB 显式指定")
    prefab = locate_dll(platform)
    if not prefab:
        raise KeyLibError(
            f"keylib 现场编译不可得且预制件缺失（{reason}）——"
            "安装平台工具链或补齐 keylib 件后重试")
    patch_dll(prefab, out_path, k_app)
    print(f"[keylib] 现场编译退化锚点补丁路径（{reason}）——件内保留锚点标记，"
          "保护面降级；建议补齐平台编译工具链")
    return "fallback"


def _stage_keylib(stage: str, code_key_id: str, platform: str = "windows", *,
                  app_id: str, salt_hex: str = "") -> int:
    """key-holder 件落位 staging + K 派生 + key_id 配对闸门（§6.2 + ★档位1 §3★）。

    ★档位1★ K 派生化：code.key 退役——现场 resolve_master_key(create=False，
    package 期缺失即 fail-fast 提示 master 准入) → derive_k_app(master, app_id,
    salt)（salt 读 spk manifest code_salt，per_build_salt 档；缺省 = 默认档常量）
    → produce_keylib 现场定制编译专属件（kdata.c 烧件），编译不可得退化为预制件
    锚点补丁。PKAPP_KEYLIB 指定的自管件（模式 B，K 编译期内嵌）原样落位不补丁。
    产出件 key_id 必须与 manifest code_key_id 一致——不一致 = 本机 master 与该
    spk 不配对（master 更换/丢失重生成），闸门拦下。
    windows 构建机可 dlopen 同平台件实测；异平台件（android .so）无法 dlopen，
    改用 Python 镜像 key_id_hex(K_app) 比对（K_app 即烧件密钥，写入正确性由
    compile/patch 两条路径的契约保证）。
    返回 0 = 成功；非 0 = 失败（调用方保留 staging 现场）。
    """
    # ★M3 定案（LINUX_M3_PLAN §4.6 条 7）★：linux 运行期件名 pkapp_key.so @ spk
    # 根（解包后 _runtime/pkapp_key.so——launcher dlopen 与 applocal ctypes 同件
    # 同源）；android 沿用 lib_pkapp_key.so（APK jniLibs 命名约定）。
    out_name = {"windows": "pkapp_key.dll", "linux": "pkapp_key.so"}.get(
        platform, "lib_pkapp_key.so")
    expect_vendored = {"windows": "_vendor/keylib/windows/pkapp_key.dll",
                       "linux": "PKAPP_KEYLIB 指定的 linux 自管件"
                       "（linux 无包内置预制件，现场编译优先）"}.get(
        platform, "PKAPP_KEYLIB 指定的 android 自管件（android 无包内置预制件）")
    try:
        try:
            salt = bytes.fromhex(salt_hex) if salt_hex else None
        except ValueError as e:
            raise KeyLibError(f"spk manifest code_salt 损坏（非法 hex）: {e}") from e
        master, _ = resolve_master_key(create=False)
        k_app = derive_k_app(master, app_id, salt)
    except KeyLibError as e:
        print(f"[package] {e}")
        return 2
    expect = key_id_hex(k_app)
    out_dll = os.path.join(stage, out_name)
    try:
        if os.environ.get("PKAPP_KEYLIB"):
            dll_path = locate_dll(platform)
            if not dll_path:
                print(f"[package] PKAPP_KEYLIB 指向的 key-holder 件不可定位"
                      f"（预期 {expect_vendored}）")
                return 2
            shutil.copyfile(dll_path, out_dll)   # 模式 B：K 已编译期内嵌，不补丁
            if platform != "windows":
                # windows 侧 ctypes 实测件本身；异平台件无法 dlopen——闸门仅验证
                # master↔manifest 配对（真机 _codekey 的 key_id 闸是第二道防线）
                print(f"[package] 警告：模式 B {platform} 件无法在本机实测，"
                      "key_id 闸门仅验证 master↔manifest 配对")
            got = KeyLib(out_dll).key_id() if platform == "windows" else expect
        else:
            mode = produce_keylib(platform, k_app, out_dll)
            if mode == "fallback":
                print(f"[package] 警告：keylib 现场编译不可得，退化为预制件锚点补丁"
                      "（件内保留锚点标记，保护面降级——PROTECTION_ROADMAP §3.3）")
            got = KeyLib(out_dll).key_id() if platform == "windows" else expect
    except (KeyLibError, OSError, AttributeError) as e:
        # AttributeError：件缺 pkapp_* 导出符号（ctypes 属性访问，模式 B 坏件）——
        # 与其余失败路径同收敛：提示语 + rc=2 + 保留 staging 现场
        print(f"[package] key-holder 件处理失败: {e}")
        return 2
    if got != code_key_id:
        print(f"[package] key-holder 配对失败：件 key_id {got[:12]}… ≠ manifest "
              f"code_key_id {code_key_id[:12]}…——本机 K_master 与该 spk 不配对"
              "（master 更换/丢失重生成；恢复正确 master 或重新 pkapp build）")
        return 2
    print(f"[package] key-holder 已配对（key_id {got[:12]}…）")
    return 0
