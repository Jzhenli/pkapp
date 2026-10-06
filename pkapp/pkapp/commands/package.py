"""pkapp package <platform>：平台终产物组装——windows→zip / android→apk / linux→tar.gz（M3）。

★v8.4★ 取代原 ship 成为三平台统一终产物命令；中间产物（spk）归 build，
本命令只做"壳 + spk → 交付容器"，产物统一落 <project>/release/。

windows（模式 A）：预编译壳 + spk 组装三件套到一次性 staging（build/staging-windows/，
rcedit 可选增强），配对自检闸门通过后打 zip（内含 <name>/ 一层目录）到 release/，
staging 成功即焚毁；失败保留现场（错误信息指向该目录）。
模式 A（零编译壳）：仓库默认壳 / 包内置壳（_vendor/shell）是 pkapp 分发件，
package 时在 staging 副本上原位补丁内置公钥为项目公钥（64 字符 ASCII hex 同长度
改写，manifest.c kPubHex）——任意项目密钥 × 零编译壳；显式 --shell / PKAPP_SHELL_EXE
指定的壳归用户管（模式 B 自编壳公钥自定），不做补丁。
出货前用壳的 --selftest-spk 做配对自检（壳内置公钥 × spk 签名），验不过不出货。

android：spk 入壳工程 assets → gradle → APK 内 spk 字节校验 → release/
（引擎 packager/apk.py；android 壳不做 spk 验签——APK 签名承担，协议 §10.2）。
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import zipfile

from .. import toolchain
from ..appspec import SpecError, load
from ..packager import sign
from ..packager.apk import ApkError, artifact_name, build_apk
from ..util import sha256_file

# manifest.c 出厂默认公钥（build.bat 不带第 2 参编译即此值）——补丁精确定位的首选锚点
_SHELL_DEFAULT_PUB = "74420a2d95acd1f090719a5041f64d923a75fb37557b021f3aeeff04821ef432"


def _find_shell(explicit: str | None) -> tuple[str | None, bool]:
    """预编译壳定位：--shell / PKAPP_SHELL_EXE / 仓库内默认 build/MyApp.exe / 包内置壳。

    返回 (壳路径, 可否公钥补丁)：显式指定的壳归用户管（模式 B，公钥编译期自定），
    不补丁；仓库默认壳与包内置壳是 pkapp 分发件，package 时可改写内置公钥。
    """
    if explicit:
        return (explicit if os.path.isfile(explicit) else None), False
    env = os.environ.get("PKAPP_SHELL_EXE")
    if env:
        return (env if os.path.isfile(env) else None), False
    repo = os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))))
    default = os.path.join(repo, "shell-windows", "build", "MyApp.exe")
    if os.path.isfile(default):
        return default, True
    from ..vendor import shell_exe
    vendored = shell_exe()
    return (vendored, True) if vendored else (None, False)


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


def _spk_manifest_fields(spk_path: str) -> dict:
    """读 spk 内 manifest 字段（package 期判定加密态：code_key_id 存在 = 加密产物）。

    读取失败按非加密处理（明文流程零新增失败模式，G6）——损坏 spk 由壳配对
    自检闸门兜底拦截。
    """
    from ..packager import manifest as mf
    from ..packager import spk as spk_mod
    try:
        entries = spk_mod.read_spk(spk_path)
        entry = next((e for e in entries if e[0] == spk_mod.MANIFEST_ENTRY), None)
        if entry is None:
            return {}
        return mf.parse(entry[1].decode("utf-8"))
    except Exception:                     # BadZipFile 等损坏包 → 按明文处理（壳自检兜底）
        return {}


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
    from ..packager.keybuild import produce_keylib
    from ..packager.keylib import (KeyLib, KeyLibError, derive_k_app,
                                   key_id_hex, locate_dll, resolve_master_key)
    out_name = "pkapp_key.dll" if platform == "windows" else "lib_pkapp_key.so"
    expect_vendored = "_vendor/keylib/windows/pkapp_key.dll" if platform == "windows" \
        else "_vendor/keylib/android/lib_pkapp_key.so"
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


def _patch_shell_pubkey(exe: str, pub_hex: str) -> None:
    """壳内置公钥原位补丁（staging 副本上调用，绝不触碰分发原件）。

    kPubHex 在 exe 内是 64 字符 ASCII hex 常量（manifest.c）——先精确命中出厂默认
    公钥；未命中（自定义 pub 编译的壳）再全文扫 64-hex 连续段，唯一段才改写
    （零段/多段 = 定位不可靠，报错引导走模式 B）。同长度改写，文件其余字节零扰动。
    """
    if len(pub_hex) != 64 or re.fullmatch(r"[0-9a-fA-F]{64}", pub_hex) is None:
        raise RuntimeError(f"公钥非法（须 64 位 hex）: {pub_hex[:16]}…")
    with open(exe, "rb") as f:
        data = f.read()
    new = pub_hex.lower().encode("ascii")
    needle = _SHELL_DEFAULT_PUB.encode("ascii")
    offsets = [m.start() for m in re.finditer(re.escape(needle), data)]
    if not offsets:
        hex_runs = list(re.finditer(rb"[0-9a-f]{64}", data))
        if len(hex_runs) != 1:
            raise RuntimeError(
                f"壳内置公钥定位失败（64-hex 连续段 ×{len(hex_runs)}）——该壳无法自动配对，"
                "请自编壳（shell-windows/build.bat <AppName> <项目公钥>）后 --shell 指定（模式 B）")
        offsets = [m.start() for m in hex_runs]
    for off in offsets:
        data = data[:off] + new + data[off + 64:]
    with open(exe, "wb") as f:
        f.write(data)


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
        return _package_windows(project, spec, shell=shell, icon=icon,
                                desc=desc, rcedit=rcedit, out=out)
    if platform == "android":
        return _package_android(project, spec, shell_dir=shell_dir,
                                variant=variant, out=out, arch=arch)
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
    shell_exe, patchable = _find_shell(shell)
    if not shell_exe:
        print("[package] 未找到预编译壳：设 PKAPP_SHELL_EXE 或 --shell <shell.exe>"
              "（wheel 安装形态由包内置壳兜底，缺失时重装 pkapp）")
        return 2
    loader = os.path.join(os.path.dirname(shell_exe), "WebView2Loader.dll")
    if not os.path.isfile(loader):
        print(f"[package] 壳旁缺 WebView2Loader.dll: {loader}")
        return 2
    # 代码加密（②）：manifest 带 code_key_id = 加密构建产物 → key-holder 件补丁进
    # staging（exe 旁）+ key_id 配对闸门；明文产物零改动（G6）
    fields = _spk_manifest_fields(spk)
    encrypted = bool(fields.get("code_key_id"))

    # 一次性组装 staging：build/staging-windows/——壳是共用预编译件，公钥补丁 /
    # rcedit 资源改写都必须在副本上做；staging 成功打 zip 后即焚毁（release/ 只放
    # 终产物 zip），失败保留现场（错误信息指向该目录），下次 package 先清残留。
    stage = os.path.join(project, "build", "staging-windows")
    shutil.rmtree(stage, ignore_errors=True)
    os.makedirs(stage, exist_ok=True)
    exe_path = os.path.join(stage, f"{name}.exe")
    shutil.copyfile(shell_exe, exe_path)
    shutil.copyfile(spk, os.path.join(stage, f"{name}.spk"))
    shutil.copyfile(loader, os.path.join(stage, "WebView2Loader.dll"))

    # 公钥补丁：分发壳（仓库默认 / 包内置）的烧录公钥改写为项目公钥——
    # 任意项目密钥 × 零编译壳；定位失败或私钥缺失时不阻断（配对自检闸门兜底）。
    if patchable:
        try:
            key_path = sign.resolve_private_key(None, project)
        except sign.SignError as e:
            print(f"[package] {e}")
            key_path = None
        if key_path is None:
            print("[package] 未定位到签名私钥（PKAPP_SIGN_KEY / .pkapp/sign.key）——"
                  "壳公钥补丁跳过，若 spk 用他钥签名配对自检会拦下")
        else:
            pub = sign.public_key_hex(key_path)
            try:
                _patch_shell_pubkey(exe_path, pub)
                print(f"[package] 壳公钥已配对项目密钥（{pub[:12]}…）")
            except (RuntimeError, OSError) as e:   # OSError：杀软/Defender 句柄锁等
                print(f"[package] 壳公钥补丁失败: {e}")
                print(f"[package] 组装 staging 保留现场: {stage}")
                return 2

    # 出货闸门：壳内置公钥必须验得过这个 spk（补丁后自检 = 验证最终出货字节）
    ok, detail = _shell_accepts(exe_path, spk)
    if not ok:
        print("[package] 配对自检失败——壳验不过该 spk（壳内置公钥 ≠ 签名公钥）。\n"
              "  模式 A：pkapp build windows（私钥缺失会自动 keygen）后重跑 package\n"
              "  模式 B：自编壳 build.bat <AppName> <项目公钥>，--shell 指定使用")
        if detail:
            print(f"  壳输出: {detail}")
        print(f"[package] 组装 staging 保留现场: {stage}")
        return 2

    # key-holder 件（仅加密产物）：现场派生 K + 专属件产出 + key_id 配对闸门
    # （★档位1★；失败保留现场）
    if encrypted:
        rc = _stage_keylib(stage, fields["code_key_id"], app_id=name,
                           salt_hex=fields.get("code_salt", ""))
        if rc != 0:
            print(f"[package] 组装 staging 保留现场: {stage}")
            return rc

    rc_tool = _find_rcedit(rcedit)
    if rc_tool:
        if _rcedit_apply(rc_tool, exe_path, icon, desc or name, version) != 0:
            print(f"[package] 组装 staging 保留现场: {stage}")
            return 1
        print(f"[package] rcedit 资源已更新（icon={bool(icon)} desc/版本={version}）")
    else:
        print("[package] 未找到 rcedit（可选增强）：图标/版本资源未改；"
              "运行 `pkapp fetch windows` 或设 PKAPP_RCEDIT / --rcedit 后重跑")

    out_dir = os.path.abspath(out or os.path.join(project, "release"))
    os.makedirs(out_dir, exist_ok=True)
    zip_path = os.path.join(out_dir, artifact_name(name, version, "windows"))
    zip_tmp = zip_path + ".tmp"
    files = [f"{name}.exe", f"{name}.spk", "WebView2Loader.dll"]
    if encrypted:
        files.append("pkapp_key.dll")          # exe 旁（§5.5；applocal ctypes 取用）
    with zipfile.ZipFile(zip_tmp, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in files:
            zf.write(os.path.join(stage, f), arcname=f"{name}/{f}")
    os.replace(zip_tmp, zip_path)

    sizes = [(f, os.path.getsize(os.path.join(stage, f))) for f in files]
    shutil.rmtree(stage, ignore_errors=True)   # 成功即焚：staging 只服务本次组装

    print(f"[package] {zip_path}  ({os.path.getsize(zip_path):,} B)")
    for f, sz in sizes:
        print(f"  {name}/{f}  ({sz:,} B)")
    print(f"[package] 运行时身份随 exe 文件名派生：数据目录 %LOCALAPPDATA%\\{name}")
    return 0


def _package_android(project: str, spec, *, shell_dir: str | None,
                     variant: str, out: str | None, arch: str | None = None) -> int:
    spk_dir = os.path.join(project, "build", "platform-android")
    spk = os.path.join(spk_dir, "runtime.spk")
    if not os.path.isfile(spk):
        print(f"[package] 未找到 spk: {spk}（先 pkapp build android）")
        return 2
    # ABI 决策链：build-meta.json（最后一次 build 记录）> TOML（旧构建兼容）。
    # spk 按单 ABI 装配（assemble 既定约束）——package 的 ABI 必须跟随"最后一次
    # build"而非 TOML 当前值，否则产生壳/包 ABI 错配的静默坏包（dlopen 才炸）
    abis = spec.android_abis
    meta_path = os.path.join(spk_dir, "build-meta.json")
    if os.path.isfile(meta_path):
        try:
            with open(meta_path, encoding="utf-8") as f:
                meta = json.load(f)
            abis = tuple(meta.get("abis") or ())
        except (ValueError, OSError) as e:
            print(f"[package] build-meta.json 不可读: {e}（删除该文件可回退 TOML abis）")
            return 2
        if not abis:
            print("[package] build-meta.json 无 abis 字段——重新 pkapp build android")
            return 2
        # spk 配对校验：meta 的 ABI 记录只对当时那次 spk 有效——spk 被替换
        # （隔次构建/手动覆盖）而 meta 未跟上时，这里拦下 ABI 错配的静默坏包
        # （android 壳不做 spk 验签，本闸门是唯一拦截点，对齐 windows 配对自检）
        want = (meta.get("spk_sha256") or "").strip()
        if want and want != "sha256:" + sha256_file(spk):
            print(f"[package] build-meta.json 与 runtime.spk 不匹配（spk_sha256 不符）——"
                  f"重新 pkapp build android 后再 package")
            return 2
    assert_arch = (arch or "").strip()
    if assert_arch and list(abis) != [assert_arch]:
        print(f"[package] --arch {assert_arch} 与 spk 构建记录不符（abis={list(abis)}）——"
              f"重新 pkapp build android --arch {assert_arch}")
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
    # android 运行时快照 = 壳模板注入的数据源；解析失败降级 None（上方已透出原因），
    # 由 apk.py fail-fast 指向 fetch
    runtime_dir = None
    try:
        from ..packager import runtime as _rt
        runtime_dir = _rt.resolve(spec, "android", abis=abis).dir
    except Exception as e:
        runtime_dir = None
        # 静默降级会让"快照在场但校验失败"（python_version 不一致等）伪装成缺快照，
        # 误导用户重跑 fetch——透出真实原因一行
        print(f"[package] android 运行时快照未解析: {e}")
    # 代码加密（②）：spk manifest 带 code_key_id = 加密构建 → key-holder .so
    # 现场派生/补丁 + key_id 闸门后交 build_apk 进 APK jniLibs（§5.5）；
    # 明文产物零改动（G6）。salt 从 spk manifest code_salt 读（per_build_salt 档）。
    spk_fields = _spk_manifest_fields(spk) or {}
    code_key_id = spk_fields.get("code_key_id", "")
    keylib_so = None
    keylib_stage = None
    if code_key_id:
        import tempfile
        keylib_stage = tempfile.mkdtemp(prefix="pkapp-keylib-android-")
        rc_kl = _stage_keylib(keylib_stage, code_key_id, "android",
                              app_id=spec.name,
                              salt_hex=spk_fields.get("code_salt", ""))
        if rc_kl != 0:
            shutil.rmtree(keylib_stage, ignore_errors=True)
            return rc_kl
        keylib_so = os.path.join(keylib_stage, "lib_pkapp_key.so")
    try:
        apk_path = build_apk(project, spec.name, spk, shell_dir=shell_dir,
                             out_dir=out_dir, variant=variant,
                             app_id=spec.android_package,
                             version=spec.version, abis=abis,
                             keystore=keystore, keystore_pass=keystore_pass,
                             keystore_alias=keystore_alias, icon=icon,
                             runtime_dir=runtime_dir, keylib_so=keylib_so)
    except ApkError as e:
        print(f"[package] APK 组装失败: {e}")
        return 1
    finally:
        if keylib_stage:
            shutil.rmtree(keylib_stage, ignore_errors=True)
    print(f"[package] {apk_path}  ({os.path.getsize(apk_path):,} B)")
    print(f"[package] 变体={variant}"
          f"{'（已用 keystore 签名）' if keystore else '（debug 自动签名；release 需 keystore：TOML [platforms.android].keystore + env PKAPP_KEYSTORE_PASS）'}；"
          "android 壳不做 spk 验签——APK 签名承担（协议 §10.2）")
    return 0
