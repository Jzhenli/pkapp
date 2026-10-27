"""packager 装配管线（协议 B §1 布局 / §5 条款 / §6 spk）——同构核心单管线。

windows 管线步骤（M1 定稿；linux/android 在 M2/M3 接入）：
  快照解析 → stage ← {解释器 DLL, stdlib zip(B.x 派生), DLLs/(B.s 闭包自检),
  _pth 四行, site-packages(pip --target + B.v certifi 断言), app/, ui/}
  → app/ checked-hash pyc(B.u) → *_hash → manifest + Ed25519 → spk(STORED)。
"""
from __future__ import annotations

import os
import secrets
import shutil
import tempfile

from ..appspec import AppSpec
from ..util import atomic_write, copy_tree, tree_hash
from . import integrity
from . import runtime
from .closure import check_closure
from .consolidate import APPLOCAL_UNIT, _consolidate_site_packages
from .deps import (_android_pip_tags, _detect_applocal, _install_site_packages,
                   _linux_pip_tags, _wheels_cache)
from .emit import _emit_spk, _manifest_fields
from .encrypt import _encrypt_app_tree, _ensure_same_runtime_version
from .errors import BuildError
from .keybuild import _stage_keylib
from .keylib import ensure_obf_key
from .pyc import (_app_hash_plaintext, _compile_checked_hash, _compile_flat_tree,
                  _zip_lib)
from .runtime import RuntimeResolveError

# 保守档精简（flet python-build 同款共识死重，258d7f5 实测 Windows -3.2MB /
# Linux -2.7MB）：工具链自举/开发工具/彩蛋——正常业务代码物理上不 import。
# ★两平台同源★（windows Lib 拷贝 + linux stdlib 拷贝共用，防清单漂移）；
# 回归锚 test_packager.test_conservative_trim_anchor 双向防丢。
_TRIM_IGNORE_LIB = ("ensurepip", "idlelib", "pydoc_data", "lib2to3",
                    "turtledemo", "rlcompleter.py", "tabnanny.py",
                    "antigravity.py", "this.py", "__hello__.py", "__phello__")


def _entry_protected_pairs(entry: str) -> frozenset:
    """entry "app.main:app" → frozenset({("app.main", "app")})（★§4.1 RFT★）：
    入口 callable 名与宿主模块名是壳引导的公开合同，跨模块改名不得触碰。"""
    if ":" not in entry:
        return frozenset()
    mid, _, obj = entry.partition(":")
    return frozenset({(mid, obj.split(".")[0])})


def _placeholder_ui(ui_dir: str) -> None:
    os.makedirs(ui_dir, exist_ok=True)
    atomic_write(os.path.join(ui_dir, "index.html"),
                 b"<!doctype html><title>pkapp</title>"
                 b"<p>pkapp placeholder ui - replace with frontend build output</p>")


def build_spk(project_dir: str, spec: AppSpec, platform: str, out_path: str, *,
              private_key: str | None = None, wheels_dir: str | None = None) -> dict:
    """完整构建。返回 manifest dict（含 spk_hash）。windows/android M1-M2；linux M3。"""
    if platform == "android":
        return _build_spk_android(project_dir, spec, out_path,
                                  private_key=private_key, wheels_dir=wheels_dir)
    if platform == "linux":
        return _build_spk_linux(project_dir, spec, out_path,
                                private_key=private_key, wheels_dir=wheels_dir)
    if platform != "windows":
        raise BuildError(f"{platform} 目标不支持（当前支持 windows/android/linux）")

    snapshot = runtime.resolve(spec, platform)
    stem = runtime.dll_stem(snapshot.python_dll)

    stage = tempfile.mkdtemp(prefix="pkapp-build-")
    lib_work = tempfile.mkdtemp(prefix="pkapp-libwork-")
    try:
        # 1) 解释器本体（布局 §3.1：与 _pth 同目录，getpath 首选 DLL 相邻路径 V3）
        shutil.copyfile(os.path.join(snapshot.dir, snapshot.python_dll),
                        os.path.join(stage, snapshot.python_dll))
        # 1b) 根目录伴生 DLL 随包（vcruntime140*.dll / python3.dll 等）——真 PBS 实测：
        # 若解释器/根目录组件动态依赖它们，缺了会在干净机器上崩（PyInstaller 同款做法）
        for fn in os.listdir(snapshot.dir):
            if fn.lower().endswith(".dll") and fn != snapshot.python_dll:
                shutil.copyfile(os.path.join(snapshot.dir, fn), os.path.join(stage, fn))
        # 2) 标准库 zip（PBS 为松散 Lib/ → packager 打成 <STEM>.zip，PACKAGER_SPEC §9）
        #    zip 内恒纯 pyc（★v0.7★）：快照解释器预编译 UNCHECKED_HASH pyc 以扁平
        #    <mod>.pyc 打入（zipimport 只认扁平 .pyc，__pycache__ 布局在 zip 内无效）。
        #    zip 内编译结果无处缓存，只带 .py = 每次启动重编译整个被引标准库（实测 ~2s）。
        #    编译走独立暂存副本（stage 外，免被 tree_hash/check_closure 扫入），不改快照本体。
        _snapshot_exe = os.path.join(snapshot.dir, "python.exe")
        shutil.copytree(os.path.join(snapshot.dir, "Lib"), lib_work,
                        ignore=shutil.ignore_patterns(
                            "site-packages", "test", "tests", "__pycache__",
                            *_TRIM_IGNORE_LIB),
                        dirs_exist_ok=True)  # mkdtemp 已建空目录
        _compile_checked_hash(lib_work, _snapshot_exe, snapshot.python_dll,
                              unchecked=True)
        _zip_lib(lib_work, os.path.join(stage, f"{stem}.zip"),
                 pyc_tag="cpython-" +
                         "".join(c for c in snapshot.python_dll if c.isdigit()))
        # 3) DLLs/（.pyd + 传递原生依赖整体拷入；闭包自检见 step 7 之后——app/ 落盘
        #    后统一扫描，扫描域含 app/（Q5），行为不变仅时序后移）。
        #    保守档精简：CPython 测试专用扩展（仅被已裁的 Lib/test 引用）
        shutil.copytree(os.path.join(snapshot.dir, "DLLs"),
                        os.path.join(stage, "DLLs"),
                        ignore=shutil.ignore_patterns(
                            "_test*.pyd", "_ctypes_test*.pyd"))
        # 4) _pth 由 5b 收拢函数生成（★P0 §4.1★：path 收窄 + 无 import site，随
        #    散件目录清单动态派生——先于收拢写死会与收拢结果脱钩）
        # 5) site-packages + B.v certifi 断言（依赖 = 公共 + 平台段追加，AppSpec §platforms）
        #    wheels_dir 缺省 → 全局托管缓存（<cache_root>/wheels/windows，跨项目/跨次构建复用）
        index_url, extra_index = spec.wheels_index(platform)
        sp_dir = _install_site_packages(stage, spec.deps_for(platform),
                                        wheels_dir or _wheels_cache(platform),
                                        allow_download=wheels_dir is None,
                                        index_url=index_url, extra_index_url=extra_index)
        if not os.path.isdir(os.path.join(sp_dir, "certifi")):
            raise BuildError("site-packages 缺 certifi（B.v 出网信任链硬约束，B.z⑥）")
        # 5b) site-packages 收拢（★P0 §4.1★）：applocal_version 探测前移（dist-info
        #     随后收进 deps.zip，importlib.metadata 扫不到散件形态）→ 纯 Python
        #     发行版收 deps.zip（内 pyc-only、剥 .py）、含原生扩展/数据文件/applocal
        #     散件化（flat pyc）、._pth 收窄（site-packages/ 本身不上 sys.path）
        applocal_version = _detect_applocal(sp_dir)
        _consolidate_site_packages(stage, sp_dir, _snapshot_exe,
                                   snapshot.python_dll, stem)
        # 6) app/ 与 ui/（packager 永不改写 app 内容；ui 恒存在。包内契约目录名 ui）
        app_src = os.path.join(project_dir, spec.app_dir)
        if not os.path.isdir(app_src):
            raise BuildError(f"项目缺 {spec.app_dir}/ 目录")
        copy_tree(app_src, os.path.join(stage, "app"))
        ui_src = os.path.join(project_dir, spec.dist_dir)
        if os.path.isdir(ui_src) and os.listdir(ui_src):
            copy_tree(ui_src, os.path.join(stage, "ui"))
        else:
            _placeholder_ui(os.path.join(stage, "ui"))
        # 7) app/ checked-hash pyc（B.u）——仅 app/（★v0.7★ site-packages 恒只带 .py，
        #    目录树首启自动建 __pycache__ 缓存，零副作用；app/ 恒保留源码，用户可内省）
        app_stage = os.path.join(stage, "app")
        # ★§13.3③ S7★ 混淆开启 → 先取混淆密钥（.pkapp/obf.key，与 code.key 平行互不依赖）
        obf_key = ensure_obf_key(project_dir) if spec.code_obfuscation else None
        obf_stats = _compile_checked_hash(app_stage, _snapshot_exe,
                                          snapshot.python_dll,
                                          obfuscate=spec.code_obfuscation,
                                          obf_key=obf_key,
                                          protected_pairs=_entry_protected_pairs(spec.entry))
        if obf_stats["renamed"] + obf_stats["stripped"] + obf_stats["strings"] > 0:
            print(f"[build] app/ 混淆：改名 {obf_stats['renamed']} 符号/"
                  f"剥离 {obf_stats['stripped']} docstring/"
                  f"加密 {obf_stats['strings']} 字符串")
        if obf_stats.get("exempt"):
            parts = " ".join(f"{k}={v}" for k, v in sorted(obf_stats["exempt"].items()))
            print(f"[build] app/ 改名豁免：{parts}")
        # 7b) app_hash（★档位1 §3.2 解耦★：加密前明文 marshal 载荷哈希——与 K
        #     彻底解耦，换 keylib 形态/换 master 均不改变 app_hash；必须在 7c 前）
        pyc_tag = "cpython-" + "".join(c for c in snapshot.python_dll if c.isdigit())
        app_hash = _app_hash_plaintext(app_stage, pyc_tag)
        # 7c) 代码加密（CODE_PROTECTION_DESIGN §6.1 + ★档位1 §3 K 派生化★，
        #     [app] code_encryption=true 才启用；缺省关闭 → 本步骤整体跳过，G6 零回归）
        code_key_id = ""
        code_salt = ""
        if spec.code_encryption:
            salt = secrets.token_bytes(32) if spec.per_build_salt else None
            if salt is not None:
                code_salt = salt.hex()     # manifest code_salt（R-2 per-build 档）
            code_key_id = _encrypt_app_tree(stage, _snapshot_exe,
                                            snapshot.python_dll,
                                            spec.name, salt)

        # 8) 树哈希 + manifest + 签名 + spk（闭包自检扫描域含 app/，Q5）
        check_closure(stage, snapshot.python_dll, extra_dirs=(app_stage,))
        runtime_hash = tree_hash(stage, excludes=("app", "ui"))
        fields = _manifest_fields(spec, "windows", snapshot.python_dll,
                                  f"sha256:{runtime_hash}",
                                  applocal_version,
                                  app_hash,
                                  os.path.join(stage, "ui"),
                                  code_key_id=code_key_id, code_salt=code_salt)
        # ★P0 §4.2★ 引导面完整性清单 + Ed25519 签名：覆盖 stage 全树（= _runtime
        # 落盘终态，含 site-packages 收拢后形态与 app/ui），随 spk 以 _integrity/
        # 前缀条目携带（package 期提取落 exe 旁；壳每启验签 + 对称差，fail-closed）
        itext = integrity.render(integrity.build_entries(stage))
        isig = integrity.sign_manifest(itext, private_key)
        return _emit_spk(stage, fields, out_path, private_key,
                         integrity_sidecar=integrity.spk_sidecar_entries(itext, isig))
    finally:
        shutil.rmtree(stage, ignore_errors=True)
        shutil.rmtree(lib_work, ignore_errors=True)


def _sha256_file(path: str) -> str:
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _build_spk_android(project_dir: str, spec: AppSpec, out_path: str, *,
                       private_key: str | None = None,
                       wheels_dir: str | None = None) -> dict:
    """Android spk（M2）：解释器级 runtime 走 APK（jniLibs 的 libpython + assets 的
    stdlib.zip/modules.zip），壳退化为引导器、验签由 APK 签名承担（SHELL_PROTOCOL §10.2）。
    spk = manifest + signature + site-packages/ + app/ + ui/——pip 依赖随应用版本走，
    必须进 spk（APK 里只放与解释器版本绑定的件）。
    runtime_hash = libpythonbundle.so 的 sha256（标识所针对的运行时 bundle）。
    """
    if len(spec.android.abis) != 1:
        raise BuildError(
            f"[platforms.android].abis 须为单 ABI（当前 {list(spec.android.abis)}）："
            "flet android 解释器的扩展后缀无 ABI 段，双 ABI 的 .so 同名冲突无法共存于"
            "同一 site-packages——一次只打包一种 ABI（多 ABI 分次构建出多个 APK）")
    snapshot = runtime.resolve(spec, "android", abis=spec.android.abis)

    stage = tempfile.mkdtemp(prefix="pkapp-build-android-")
    try:
        # 1) site-packages + B.v certifi 断言（依赖 = 公共 + [platforms.android] 追加）
        #    wheels_dir 缺省 → 托管缓存（<cache_root>/wheels/android/<abi>，按 abi
        #    分层防跨 ABI 互踩）；交叉安装 + 平台 wheel 源（AppSpec
        #    [platforms.android].extra_index_url，如 flet 索引）
        index_url, extra_index = spec.wheels_index("android")
        sp_dir = _install_site_packages(stage, spec.deps_for("android"),
                                        wheels_dir or _wheels_cache("android",
                                                                   spec.android.abis[0]),
                                        allow_download=wheels_dir is None,
                                        pip_tags=_android_pip_tags(spec),
                                        index_url=index_url, extra_index_url=extra_index)
        if not os.path.isdir(os.path.join(sp_dir, "certifi")):
            raise BuildError("site-packages 缺 certifi（B.v 出网信任链硬约束，B.z⑥）")
        # 2) app/ 与 ui/（同 windows：packager 永不改写 app 内容；ui 恒存在）
        app_src = os.path.join(project_dir, spec.app_dir)
        if not os.path.isdir(app_src):
            raise BuildError(f"项目缺 {spec.app_dir}/ 目录")
        copy_tree(app_src, os.path.join(stage, "app"))
        ui_src = os.path.join(project_dir, spec.dist_dir)
        if os.path.isdir(ui_src) and os.listdir(ui_src):
            copy_tree(ui_src, os.path.join(stage, "ui"))
        else:
            _placeholder_ui(os.path.join(stage, "ui"))
        # 3) app/ checked-hash pyc（B.u）。android 快照无 python.exe——借用 windows 快照解释器
        #   （版本哨兵按 python_dll 名校验 3.12 == 3.12，pyc 字节与平台无关）；
        #   两端快照版本互等由防线 A 锁定；未注册 windows 快照时回退打包机解释器，
        #   版本比对由防线 B 锁定（不符 BuildError，不再静默）。
        #   site-packages 恒只带 .py（★v0.7★：目录树首启自动建 __pycache__，零副作用）。
        pyc_exe = None
        try:
            win = runtime.resolve(spec, "windows")
            pyc_exe = os.path.join(win.dir, "python.exe")
            # ★review 后补防线 A★ Windows 快照代编 Android 的 pyc——两端快照
            # 版本互等（resolve 已各自锁"快照↔声明"，这里锁两端）。
            if spec.code_encryption:
                _ensure_same_runtime_version(win.python_version,
                                             snapshot.python_version)
        except RuntimeResolveError:
            pass
        # ★§13.3③ S7★ 混淆开启 → 先取混淆密钥（.pkapp/obf.key，与 code.key 平行互不依赖）
        obf_key = ensure_obf_key(project_dir) if spec.code_obfuscation else None
        obf_stats = _compile_checked_hash(os.path.join(stage, "app"), pyc_exe,
                                          snapshot.python_dll,
                                          obfuscate=spec.code_obfuscation,
                                          obf_key=obf_key,
                                          protected_pairs=_entry_protected_pairs(spec.entry))
        if obf_stats["renamed"] + obf_stats["stripped"] + obf_stats["strings"] > 0:
            print(f"[build] app/ 混淆：改名 {obf_stats['renamed']} 符号/"
                  f"剥离 {obf_stats['stripped']} docstring/"
                  f"加密 {obf_stats['strings']} 字符串")
        if obf_stats.get("exempt"):
            parts = " ".join(f"{k}={v}" for k, v in sorted(obf_stats["exempt"].items()))
            print(f"[build] app/ 改名豁免：{parts}")

        # 3′) applocal flat pyc-only + §13 期1 混淆（★applocal 出货混淆★）：android
        #     不走收拢，site-packages 其余依赖保持 .py（v0.7 布局）；applocal 恒
        #     pyc-only 与 windows loose/ 同形态（SourcelessFileLoader 目录 flat pyc
        #     合法形态）——消灭 .py 明文源码面；_codekey.pyc 供
        #     _encrypt_applocal_boot 直读分支（3b 加密前必须完成）。
        al_st = _compile_flat_tree(os.path.join(sp_dir, APPLOCAL_UNIT), pyc_exe,
                                   snapshot.python_dll, obfuscate=True)
        if al_st["renamed"] + al_st["stripped"] > 0:
            print(f"[build] applocal 混淆：改名 {al_st['renamed']} 符号/"
                  f"剥离 {al_st['stripped']} docstring")

        # 3a) app_hash（★档位1 §3.2 解耦★）——必须在 3b 加密前（加密删明文）
        pyc_tag = "cpython-" + "".join(c for c in snapshot.python_dll if c.isdigit())
        app_hash = _app_hash_plaintext(os.path.join(stage, "app"), pyc_tag)

        # 3b) 代码加密（CODE_PROTECTION_DESIGN §6.1 + ★档位1 §3 K 派生化★，
        #     android 与 windows 同链）。加密器 = 构建机本机 keylib 件
        #     （_encrypt_app_tree 恒用构建机件，密文字节与目标平台无关）；
        #     运行期件 lib_pkapp_key.so 由 package 期现场派生/补丁后进 APK
        #     jniLibs（§5.5，APK 签名覆盖其完整性）。
        code_key_id = ""
        code_salt = ""
        if spec.code_encryption:
            salt = secrets.token_bytes(32) if spec.per_build_salt else None
            if salt is not None:
                code_salt = salt.hex()     # manifest code_salt（R-2 per-build 档）
            code_key_id = _encrypt_app_tree(stage, pyc_exe,
                                            snapshot.python_dll,
                                            spec.name, salt)

        # 4) manifest + 签名 + spk
        bundle = os.path.join(snapshot.dir, snapshot.abis[0], "libpythonbundle.so")
        fields = _manifest_fields(spec, "android", snapshot.python_dll,
                                  f"sha256:{_sha256_file(bundle)}",
                                  _detect_applocal(sp_dir),
                                  app_hash,
                                  os.path.join(stage, "ui"),
                                  code_key_id=code_key_id, code_salt=code_salt)
        return _emit_spk(stage, fields, out_path, private_key)   # android 无侧车（Q3 不进 P0）
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def _build_spk_linux(project_dir: str, spec: AppSpec, out_path: str, *,
                     private_key: str | None = None,
                     wheels_dir: str | None = None) -> dict:
    """Linux spk（M3 阶段 2；LINUX_M3_PLAN §4.6 条 4/7 定案 + §5 差异点清单）。

    windows 同构管线全复用（deps.zip + loose 收拢 + applocal + 加密链 + 侧车），
    差异点：
    - 快照 <arch>/ 布局：libpython 真件在 <arch>/lib/、stdlib 在 <arch>/lib/python3.12/
      （runtime.resolve R-L17 已按 arch 解析）；
    - manifest python_dll = libpython3.12.so.1.0（launcher dlopen _runtime/<键>）；
    - stdlib zip 名恒 python312.zip（定案）；
    - 无根伴生 DLL / DLLs/（PBS linux 扩展静态编入 libpython，动态扩展走
      lib-dynload/ 整体拷入）；
    - spk 内无 ._pth（★D-5★ 部署态 <launcher 名>._pth 由 package 期生成，引用
      _runtime/ 内条目）——consolidate 产出的 windows 形态 _pth 落 stage 即删；
    - 编译面解释器 = windows 快照 python.exe 借编（pyc 字节与目标平台无关，
      android 同款先例；哨兵按"编译器实际版本"校验——pyc.py 已修 .so 版本链归一）；
    - wheels 平台标签 manylinux2014_<arch>（D-12 v5 PyPI 交叉下载主路线）；
    - 加密态：运行期 keylib 件 pkapp_key.so 烧 K 进 spk 根（§4.6 条 7——launcher
      dlopen 与 applocal ctypes 同件同源）；供给序 = host 同 arch 现场编译 >
      per-arch 预制件锚点补丁（_vendor/keylib/linux/<arch>，CI launcher job
      同容器编译收录）> fail-fast 指路（2026-10 D-3 边界修订：nt host 加密态
      亦可用包内置预制件出包）。
    - tcl/tk 运行期库不进 spk（冒烟定案口径，smoke spk 无 tcl/tk）——_tkinter.so +
      tkinter/ + turtle.py 同步裁除（防"打包成功、运行期 dlopen libtcl 失败"炸弹）；
      tk 支持随 spec 开关另议（须连带 6.99MB tcl/tk 全家 + TCL_LIBRARY 路径）。
    - linux 闭包自检（ELF DT_NEEDED 扫描）随后续接线——本阶段动态扩展集 =
      _crypt/_dbm（libc 族依赖），冒烟定案已实证加载链。
    """
    if len(spec.linux.abis) != 1:      # 数据层已拦（LinuxSpec.validate），防御同 android
        raise BuildError(f"[platforms.linux].abis 须为单架构（当前 {list(spec.linux.abis)}）")
    snapshot = runtime.resolve(spec, "linux", abis=spec.linux.abis)
    arch = spec.linux.abis[0]
    # 编译面解释器 = windows 快照 python.exe 借编（缺 windows 快照回退打包机解释器，
    # 版本比对由哨兵锁定）。pyc_dll 恒描述"实际编译器"（哨兵语义），manifest 用
    # linux 真名。
    pyc_exe = None
    pyc_dll = "python312.dll"
    try:
        win = runtime.resolve(spec, "windows")
        pyc_exe = os.path.join(win.dir, "python.exe")
        pyc_dll = win.python_dll
        if spec.code_encryption:
            _ensure_same_runtime_version(win.python_version, snapshot.python_version)
    except RuntimeResolveError:
        pass
    pyc_tag = "cpython-" + "".join(snapshot.python_version.split(".")[:2])
    # stdlib 目录/zip 名派生（防族锁升级漂移：review #5——"3.12.14" → lib "python3.12"
    # / stem "python312"，快照实际版本为源，与 pin 对账一致由 resolve 保证）
    maj_min = ".".join(snapshot.python_version.split(".")[:2])     # "3.12"
    stdlib_stem = "python" + maj_min.replace(".", "")              # "python312"

    stage = tempfile.mkdtemp(prefix="pkapp-build-linux-")
    lib_work = tempfile.mkdtemp(prefix="pkapp-libwork-linux-")
    try:
        # 1) libpython 真件 → spk 根（定案条 4；launcher dlopen _runtime/<python_dll>）
        shutil.copyfile(os.path.join(snapshot.dir, "lib", snapshot.python_dll),
                        os.path.join(stage, snapshot.python_dll))
        # 2) 标准库 zip（<arch>/lib/python<maj_min>/ → <stdlib_stem>.zip；保守档清单与
        #    windows 同源（_TRIM_IGNORE_LIB）；linux 特有排除：lib-dynload/config-*/
        #    tkinter/turtle——见本函数 docstring）
        shutil.copytree(os.path.join(snapshot.dir, "lib", f"python{maj_min}"),
                        lib_work,
                        ignore=shutil.ignore_patterns(
                            "site-packages", "test", "tests", "__pycache__",
                            *_TRIM_IGNORE_LIB,
                            # linux 布局特有：
                            "lib-dynload",            # 动态扩展单独拷（步骤 3）
                            "config-*",               # 构建配置/静态库，运行期无用
                            "tkinter", "turtle.py",   # tcl/tk 运行期库不进 spk（见 docstring）
                        ),
                        dirs_exist_ok=True)  # mkdtemp 已建空目录
        _compile_checked_hash(lib_work, pyc_exe, pyc_dll, unchecked=True)
        _zip_lib(lib_work, os.path.join(stage, f"{stdlib_stem}.zip"), pyc_tag=pyc_tag)
        # 3) lib-dynload/（动态扩展整体拷入；.empty 占位/测试扩展/_tkinter 裁除）
        dyn_src = os.path.join(snapshot.dir, "lib", f"python{maj_min}", "lib-dynload")
        if os.path.isdir(dyn_src):
            shutil.copytree(dyn_src, os.path.join(stage, "lib-dynload"),
                            ignore=shutil.ignore_patterns(
                                ".empty", "_test*", "_ctypes_test*", "_tkinter*"))
        # 4) site-packages + B.v certifi 断言（依赖 = 公共 + [platforms.linux]；
        #    wheels_dir 缺省 → 托管缓存 <root>/wheels/linux/<arch>）
        index_url, extra_index = spec.wheels_index("linux")
        deps = spec.deps_for("linux")
        sp_dir = _install_site_packages(stage, deps,
                                        wheels_dir or _wheels_cache("linux", arch),
                                        allow_download=wheels_dir is None,
                                        pip_tags=_linux_pip_tags(spec, arch),
                                        index_url=index_url,
                                        extra_index_url=extra_index)
        if not os.path.isdir(os.path.join(sp_dir, "certifi")):
            raise BuildError("site-packages 缺 certifi（B.v 出网信任链硬约束，B.z⑥）")
        # 5) 收拢（windows 同构：deps.zip + site-packages/loose/ + applocal flat
        #    pyc）；linux spk 不携带 ._pth（D-5）——consolidate 的 windows 形态
        #    _pth 落 stage 即删（不进 tree_hash/integrity 面）
        applocal_version = _detect_applocal(sp_dir)
        _consolidate_site_packages(stage, sp_dir, pyc_exe, pyc_dll, stdlib_stem)
        gen_pth = os.path.join(stage, f"{stdlib_stem}._pth")
        if os.path.isfile(gen_pth):
            os.remove(gen_pth)
        # 6) app/ 与 ui/（同 windows：packager 永不改写 app 内容；ui 恒存在）
        app_src = os.path.join(project_dir, spec.app_dir)
        if not os.path.isdir(app_src):
            raise BuildError(f"项目缺 {spec.app_dir}/ 目录")
        copy_tree(app_src, os.path.join(stage, "app"))
        ui_src = os.path.join(project_dir, spec.dist_dir)
        if os.path.isdir(ui_src) and os.listdir(ui_src):
            copy_tree(ui_src, os.path.join(stage, "ui"))
        else:
            _placeholder_ui(os.path.join(stage, "ui"))
        # 7) app/ checked-hash pyc（B.u）+ 混淆（同 windows；编译器 = 借编 exe）
        app_stage = os.path.join(stage, "app")
        obf_key = ensure_obf_key(project_dir) if spec.code_obfuscation else None
        obf_stats = _compile_checked_hash(app_stage, pyc_exe, pyc_dll,
                                          obfuscate=spec.code_obfuscation,
                                          obf_key=obf_key,
                                          protected_pairs=_entry_protected_pairs(spec.entry))
        if obf_stats["renamed"] + obf_stats["stripped"] + obf_stats["strings"] > 0:
            print(f"[build] app/ 混淆：改名 {obf_stats['renamed']} 符号/"
                  f"剥离 {obf_stats['stripped']} docstring/"
                  f"加密 {obf_stats['strings']} 字符串")
        if obf_stats.get("exempt"):
            parts = " ".join(f"{k}={v}" for k, v in sorted(obf_stats["exempt"].items()))
            print(f"[build] app/ 改名豁免：{parts}")
        # 7b) app_hash（加密前明文 marshal 载荷哈希——与 K 解耦，档位1 §3.2）
        app_hash = _app_hash_plaintext(app_stage, pyc_tag)
        # 7c) 代码加密 + 运行期 keylib 件烧 K 进 spk 根（§4.6 条 7）
        code_key_id = ""
        code_salt = ""
        if spec.code_encryption:
            salt = secrets.token_bytes(32) if spec.per_build_salt else None
            if salt is not None:
                code_salt = salt.hex()     # manifest code_salt（R-2 per-build 档）
            code_key_id = _encrypt_app_tree(stage, pyc_exe, pyc_dll,
                                            spec.name, salt)
            rc = _stage_keylib(stage, code_key_id, "linux",
                               app_id=spec.name, salt_hex=code_salt,
                               arch=arch)
            if rc != 0:
                raise BuildError(
                    "linux 运行期 keylib 件不可得：现场编译需 linux 工具链"
                    "（WSL2/CI），per-arch 预制件缺失（重跑 pkapp/scripts/"
                    "vendor.py 或 CI launcher job artifact），或以 PKAPP_KEYLIB "
                    "指定自管件")
        # 8) 树哈希 + manifest + 侧车 + spk（linux 闭包 ELF 扫描随后续接线，
        #    见 docstring；spk_hash 排除口径由 emit 统一承担——§4.6 条 3）
        runtime_hash = tree_hash(stage, excludes=("app", "ui"))
        fields = _manifest_fields(spec, "linux", snapshot.python_dll,
                                  f"sha256:{runtime_hash}",
                                  applocal_version,
                                  app_hash,
                                  os.path.join(stage, "ui"),
                                  code_key_id=code_key_id, code_salt=code_salt)
        itext = integrity.render(integrity.build_entries(stage))
        isig = integrity.sign_manifest(itext, private_key)
        return _emit_spk(stage, fields, out_path, private_key,
                         integrity_sidecar=integrity.spk_sidecar_entries(itext, isig))
    finally:
        shutil.rmtree(stage, ignore_errors=True)
        shutil.rmtree(lib_work, ignore_errors=True)
