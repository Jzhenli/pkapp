"""APK 组装引擎（★v8.5★，pkapp package android 的实现）：壳模板 → 注入运行时 → spk 入壳 assets → gradle → 验收落 release/。

壳模板解析顺序：--shell-dir > PKAPP_SHELL_DIR > 仓库 shell-android/shell >
wheel 内置 _vendor/shell-android（android_shell.vendored_template_dir）。
模板一律为裸源码形态（★方案A★）：构建前先物化到 <cache>/shells/android/<指纹>/
并注入托管运行时（android_shell.py）。

壳工程（gradle）与安卓工具链是构建机环境，路径解析顺序：显式参数 > 环境变量
（PKAPP_SHELL_DIR / PKAPP_ANDROID_TOOLCHAIN）> toolchain 默认布局。

资产增量陷阱（真机踩坑沉淀）：拷贝保留源文件 mtime，构建后拷入的 assets 可能被
增量 mergeDebugAssets 漏掉——拷入后必须 touch assets 目录，且组装完成后以
"APK 内 assets/runtime.spk 与源 spk 字节一致"作硬校验，漏掉即报错而非真机白屏。
"""
from __future__ import annotations

import os
import shutil
import time
import zipfile

# 壳工程随仓库分发，默认取仓库内 shell-android/shell（apk.py 位于 <repo>/pkapp/pkapp/packager/）
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))))
DEFAULT_SHELL_DIR = os.path.join(_REPO_ROOT, "shell-android", "shell")

# 物化壳目录构建锁（★方案A★ review 加固）：物化目录 <cache>/shells/android/android-<fp>/
# 跨项目共享（指纹=模板×运行时×abis，不含项目身份），并发构建互踩（runtime.spk 覆写 /
# gradle app/build 冲突）→ O_CREAT|O_EXCL 原子互斥；残留锁超时自愈（gradle 正常 ≤900s
# 超时，远小于阈值）。残余缺口：两个同指纹冷物化同时进行仍可能互踩（锁在物化之后）。
_LOCK_NAME = ".pkapp-build.lock"
_LOCK_STALE_S = 3600


def _toolchain_paths() -> dict:
    """gradle 构建工具链路径：PKAPP_ANDROID_TOOLCHAIN（旧整体根语义，手工布置）
    > toolchain 托管布局（pkapp fetch android 产物）。缺 gradle 时文案指向 fetch。"""
    from .. import toolchain

    tc = os.environ.get("PKAPP_ANDROID_TOOLCHAIN")
    if tc:
        root = os.path.join(tc, "jdk", "jdk-17.0.20.1+1")
        return {"java_home": root,
                "android_home": os.path.join(tc, "android-sdk"),
                "gradle": os.path.join(tc, "gradle-8.9", "bin",
                                       "gradle.bat" if os.name == "nt" else "gradle"),
                "gradle_home": os.path.join(tc, "gradle-home")}
    return toolchain.android_paths()


class ApkError(RuntimeError):
    """APK 组装失败（壳工程缺失 / gradle 失败 / 资产未入包）。"""


def artifact_name(name: str, version: str, platform: str,
                  abis: tuple[str, ...] = ()) -> str:
    """终产物命名：{name}-{version}-{platform}-{arch}.{ext}——平台/架构一目了然。

    android arch = abi 列表拼接（abi 内 '-' 转 '_'，如 arm64_v8a-x86_64）；
    windows 固定 x86_64（PBS pin 当前仅 x86_64-pc-windows-msvc）。
    """
    if platform == "android":
        arch = "-".join(a.replace("-", "_") for a in abis) or "universal"
        ext = "apk"
    else:
        arch, ext = "x86_64", "zip"
    return f"{name}-{version}-{platform}-{arch}.{ext}"


def _acquire_shell_lock(shell: str) -> str:
    """物化目录互斥锁：返回锁文件路径（构建毕由调用方删除）。

    新鲜锁在场 → ApkError 指向并发互斥语义（而非神秘 gradle 失败）；陈旧锁（崩溃
    残留，超 _LOCK_STALE_S）→ 接管自愈。接管竞争由下一轮 O_EXCL 天然裁决。
    """
    lock = os.path.join(shell, _LOCK_NAME)
    for _ in range(2):
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            if os.path.getmtime(lock) >= time.time() - _LOCK_STALE_S:
                raise ApkError(f"物化壳目录正被另一 pkapp 构建占用（{lock}）——"
                               "同指纹目录跨项目共享，勿并发构建；确认无并发后"
                               "删除锁文件重试")
            os.remove(lock)     # 崩溃残留的陈旧锁 → 自愈接管
            continue
        os.write(fd, str(os.getpid()).encode())
        os.close(fd)
        return lock
    raise ApkError(f"构建锁接管失败（{lock}）——请重试")


def build_apk(project: str, app_name: str, spk_path: str, *,
              shell_dir: str | None = None, out_dir: str | None = None,
              variant: str = "debug", app_id: str = "",
              version: str = "", abis: tuple[str, ...] = (),
              keystore: str = "", keystore_pass: str = "",
              keystore_alias: str = "pkapp", icon: str = "",
              runtime_dir: str | None = None,
              keylib_so: str | None = None) -> str:
    """壳模板 → 注入运行时 → spk 入壳 assets → gradle → <project>/release/<artifact_name>
    （如 HiApp-0.1.0-android-arm64_v8a.apk，★产物命名带版本/平台/架构★）。

    runtime_dir = android 托管运行时快照根（package.py 经 runtime.resolve 传入）——
    注入的数据源；缺失时 materialize fail-fast 指向 fetch。

    app_id = [platforms.android].package（必填；经 -PpkappAppId 注入 gradle
    applicationId，★v1.2★ 解决多应用同机共存——固定 com.pkapp.shell 会互相顶替）。
    keystore 链（★v1.2★）：keystore = PKAPP_KEYSTORE env > TOML [platforms.android].keystore
    （路径非机密可进 TOML；密码/别名只走 env，永不入 AppSpec）——非空时 gradle 注入
    -PpkappKs/-PpkappKsPass/-PpkappKsAlias，release 变体即产出已签名 APK。
    icon = [platforms.android].icon（PNG 路径）：经 _stage_icon_res 生成启动器图标组
    （全密度 mipmap + anydpi-v26 自适应图标，icons.py）并注入 -PpkappIconRes +
    -PpkappIcon（manifest android:icon → @mipmap/ic_app）。
    keylib_so = K 补丁后的 key-holder 件（仅加密构建，package.py _stage_keylib 产出）：
    拷入壳模板 jniLibs/<abi>/lib_pkapp_key.so 随 APK 打包——jniLibs 由系统按
    nativeLibraryDir 揭出（MYAPP_NATIVE_LIB_DIR 指向），app 数据目录 noexec
    不能落可执行 .so，故必须走 jniLibs。
    返回 APK 路径；任何一步失败抛 ApkError（gradle 输出尾部随异常给出）。
    """
    if not app_id:
        raise ApkError("[platforms.android].package 必填（applicationId，反向域名，"
                       "如 com.example.hiapp）——固定共享 applicationId 会让同机"
                       "多应用互相覆盖安装")
    if keystore and not keystore_pass:
        raise ApkError("提供 keystore 时必须同时提供密码"
                       "（env PKAPP_KEYSTORE_PASS；密码永不写入 AppSpec）")
    from . import android_shell

    src = (shell_dir or os.environ.get("PKAPP_SHELL_DIR")
           or (DEFAULT_SHELL_DIR if os.path.isdir(DEFAULT_SHELL_DIR) else None)
           or android_shell.vendored_template_dir())
    gradle_py = os.path.join(src or "", "build.gradle.kts")
    app_gradle = os.path.join(src or "", "app", "build.gradle.kts")
    if not src or not os.path.isfile(gradle_py) or not os.path.isfile(app_gradle):
        raise ApkError(f"壳模板缺失或不完整（{src or '无候选'}：缺 {gradle_py} 或 "
                       f"{app_gradle}）；可用 --shell-dir 或 PKAPP_SHELL_DIR 指定壳模板根")
    try:
        shell = android_shell.materialize(src, runtime_dir, abis)
    except android_shell.AndroidShellError as e:
        raise ApkError(str(e)) from None

    lock = _acquire_shell_lock(shell)   # 物化目录跨项目共享 → 构建期互斥
    try:
        with open(spk_path, "rb") as f:
            spk_bytes = f.read()
        assets = os.path.join(shell, "app", "src", "main", "assets")
        # 拷入 + touch 目录（绕过增量 mergeDebugAssets 的 mtime 盲区）
        os.makedirs(assets, exist_ok=True)
        with open(os.path.join(assets, "runtime.spk"), "wb") as f:
            f.write(spk_bytes)
        os.utime(assets, None)
        # key-holder 件（仅加密构建）：补丁后 .so 进 jniLibs/<abi>/（单 ABI 约束
        # 同 spk；touch 防增量 merge 的 mtime 盲区，同 assets 陷阱）。物化目录
        # 跨构建复用且指纹不含加密态——明文构建必须清掉上一次加密构建的残件，
        # 否则 K⊕MASK 随明文 APK 分发（G6 泄漏）。
        jni = os.path.join(shell, "app", "src", "main", "jniLibs", abis[0])
        so_dst = os.path.join(jni, "lib_pkapp_key.so")
        if keylib_so:
            os.makedirs(jni, exist_ok=True)
            shutil.copyfile(keylib_so, so_dst)
            os.utime(jni, None)
        elif os.path.exists(so_dst):
            os.remove(so_dst)
            os.utime(jni, None)

        _run_gradle(shell, variant, app_id, app_name,
                    keystore if keystore else None,
                    keystore_pass if keystore else "",
                    keystore_alias if keystore else "",
                    _stage_icon_res(project, icon) if icon else None, abis)

        apk_src = os.path.join(shell, "app", "build", "outputs", "apk", variant,
                               f"app-{variant}.apk")
        if not os.path.isfile(apk_src):
            unsigned = os.path.join(shell, "app", "build", "outputs", "apk", variant,
                                    f"app-{variant}-unsigned.apk")
            if os.path.isfile(unsigned):
                raise ApkError(f"检测到未签名产物 {unsigned}——keystore 未注入 gradle？")
            raise ApkError(f"gradle 未产出 {apk_src}")
        _verify_asset_in_apk(apk_src, spk_bytes)

        dest_dir = out_dir or os.path.join(project, "release")
        os.makedirs(dest_dir, exist_ok=True)
        dest = os.path.join(dest_dir, artifact_name(app_name, version, "android", abis))
        shutil.copyfile(apk_src, dest)
        return dest
    finally:
        if lock:
            try:
                os.remove(lock)
            except OSError:
                pass


def _stage_icon_res(project: str, icon: str) -> str:
    """单源 PNG → 启动器图标组（icons.py，Briefcase 同式：全密度 mipmap 位图 +
    anydpi-v26 自适应图标），暂存 <project>/build/platform-android/icon-res/。

    gradle 经 -PpkappIconRes 挂 variant sourceSet、-PpkappIcon 把 manifest
    android:icon 切到 @mipmap/ic_app（未配置时 placeholder 默认回退壳矢量图）。
    """
    from .icons import IconError, generate_android_icons

    res_dir = os.path.join(os.path.abspath(project), "build", "platform-android",
                           "icon-res")
    try:
        generate_android_icons(icon, res_dir)
    except IconError as e:
        raise ApkError(str(e)) from None
    return res_dir


def _run_gradle(shell: str, variant: str, app_id: str, label: str,
                keystore: str | None = None, keystore_pass: str = "",
                keystore_alias: str = "", icon_res: str | None = None,
                abis: tuple[str, ...] = ()) -> None:
    """转发 gradle assemble<Variant>；-PpkappAppId/-PpkappLabel 注入 applicationId/
    应用显示名（★v1.2★）；-PpkappAbis 注入 ndk.abiFilters（★方案A★，裸模板按注入的
    abi 集构建；缺省壳回退 arm64-v8a）；icon_res 非空时经 -PpkappIconRes 注入图标组资源目录 +
    -PpkappIcon 把 manifest android:icon placeholder 切到 @mipmap/ic_app；keystore
    非空时经 ORG_GRADLE_PROJECT_pkappKs/Pass/Alias 环境变量注入（gradle 映射为同名
    project property，findProperty 原样可读）——密码不进命令行，防同机进程列表
    （WMI/任务管理器）泄露；工具链路径 = env > 默认 toolchain 布局。"""
    import subprocess

    tp = _toolchain_paths()
    env = dict(os.environ)
    env.setdefault("JAVA_HOME", tp["java_home"])
    env.setdefault("ANDROID_HOME", tp["android_home"])
    env.setdefault("GRADLE_USER_HOME", tp["gradle_home"])
    gradle = tp["gradle"]
    if not os.path.isfile(gradle):
        raise ApkError(f"gradle 不存在: {gradle}——先 `pkapp fetch android`"
                       "（或设 PKAPP_ANDROID_TOOLCHAIN 指向手工布置的整体根）")
    if keystore:
        env["ORG_GRADLE_PROJECT_pkappKs"] = keystore
        env["ORG_GRADLE_PROJECT_pkappKsPass"] = keystore_pass
        env["ORG_GRADLE_PROJECT_pkappKsAlias"] = keystore_alias
    props = [f"-PpkappAppId={app_id}", f"-PpkappLabel={label}"]
    if abis:
        props.append(f"-PpkappAbis={','.join(abis)}")
    if icon_res:
        props += [f"-PpkappIconRes={icon_res}", "-PpkappIcon=@mipmap/ic_app"]
    r = subprocess.run([gradle, "--no-daemon", "-p", shell, *props,
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
