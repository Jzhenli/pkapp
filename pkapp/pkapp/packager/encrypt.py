"""app/ 代码加密（★档位1 §6★ KDF 逐文件 AES-CTR，拆分前居于 assemble）。

master（PKAPP_MASTER_KEY / ~/.pkapp/master.key）→ K_app = HKDF-SHA256 现场派生
→ keylib 现场定制编译专属件（kdata.c 烧件）→ 逐 .py 消费已编译 checked-hash
pyc、剥 16 字节头 → pk_x1 加密 → 回验闸（GCM 打开 + marshal 成 code object）→
才删明文 → index.enc 清单。两端运行时 minor 互等闸（Windows 快照代编 Android
pyc）在这里。
"""
from __future__ import annotations

import marshal
import os
import shutil
import tempfile
import types

from ..util import walk_files
from .errors import BuildError
from .keybuild import produce_keylib
from .keylib import (APPLOCAL_BOOT_MID, INDEX_FILE_NAME, INDEX_MODULE_ID,
                     KeyLib, KeyLibError, blob_name, build_index_payload,
                     derive_k_app, module_id_for, resolve_master_key)
from .pyc import _compile_one_pyc


def _ensure_same_runtime_version(win_version: str, android_version: str) -> None:
    """加密 blob 的 pyc 版本绑定运行时 minor（marshal/bytecode 随 minor 变）——
    Windows 快照解释器代编 Android 的 pyc，两端快照 minor 必须一致。

    resolve 已各自锁"快照↔声明"；本函数锁"两端互等"。比较粒度 = major.minor
    （marshal 兼容粒度；patchlevel 差异无碍）。不符直接 BuildError（fail-fast，
    防静默产出运行期才炸的载荷）。
    """
    def minor(v: str) -> tuple[int, int]:
        parts = (v.split(".") + ["0", "0"])[:2]
        return (int(parts[0]), int(parts[1]))

    if minor(win_version) != minor(android_version):
        raise BuildError(
            f"代码加密要求两端运行时 Python minor 版本一致：Windows 快照 "
            f"{win_version} ≠ Android 快照 {android_version}——统一"
            f" [platforms.*].python_version 后重新 fetch 快照")


def _encrypt_app_tree(stage: str, python_exe: str | None, python_dll: str,
                      app_id: str, salt: bytes | None = None) -> str:
    """代码加密主步骤（CODE_PROTECTION_DESIGN §6.1 + ★档位1 §3 K 派生化★）。

    流程：resolve_master_key（env > ~/.pkapp/master.key；构建期缺失即 keygen）→
    derive_k_app(master, app_id, salt)（HKDF-SHA256；K_master 永不入包）→
    produce_keylib 现场定制编译专属件（kdata.c 烧件；编译不可得退化为预制件
    锚点补丁）→ 逐模块 剥 16 字节 pyc 头 → 件加密导出 pk_x1（module_id 作
    确定性 nonce 派生 + AAD）→ 落 <sha256(mid)>.enc → 解密回读验证（GCM 打开 +
    marshal 成功）→ 才删该模块明文 .py/.pyc（顺序硬约束：明文不允许越过"已验证
    密文"这道闸）→ 全量完成后落加密清单 index.enc + 删明文闸。
    非 .py 资源明文保留（Q2）。返回 code_key_id（manifest 写入，§7.3 配对校验）。

    ★档位1★ code.key 退役：K 恒现场派生、不持久化——同 (master, app_id, salt)
    恒同 K（G5 默认档）；横向隔离由 HKDF info=app_id 承担（§1.1 防线分工）。
    加密器恒为构建机本平台件（密文字节与目标平台无关，android 构建同此路径）。

    尾部追加 ★期1 S2：_codekey 密文化★（解密根出 Python 明文面，§5.6）——
    同一件 kl / 同一 K_app 加密 site-packages/applocal/_codekey.py 为引导 blob，
    运行期壳经 keylib pk_x4 装载（装载语义归壳，keylib 停在 marshal.loads 之前）。

    G5 依赖链：pyc 载荷（PYTHONHASHSEED=0 子进程编译 + dfile=rel）与 nonce
    （HMAC(K, mid)）双确定性 → 密文字节跨构建稳定（默认 salt 档）。
    """
    stage_app = os.path.join(stage, "app")
    master, generated = resolve_master_key(create=True)
    if generated:
        print("[build] K_master 已自动生成（~/.pkapp/master.key）——请务必备份："
              "丢失 = 该构建机无法再派生与既有 spk 配对的 K（全量重加密/重打包）")
    k_app = derive_k_app(master, app_id, salt)
    work = tempfile.mkdtemp(prefix="pkapp-keylib-")
    try:
        dll_path = os.path.join(work, "pkapp_key.dll")
        # 加密器件平台 = 构建机本平台（密文字节与目标平台无关，android 构建同此路径）；
        # 构建机矩阵 = windows/linux（mac 不在支持面）——非 Windows 构建机走 linux
        # 编译器链（keybuild._compile_linux）+ ctypes 加载本平台 .so
        host = "windows" if os.name == "nt" else "linux"
        try:
            mode = produce_keylib(host, k_app, dll_path)
        except KeyLibError as e:
            raise BuildError(f"key-holder 件产出不可得（§8 构建期判定，"
                             f"不静默降级）: {e}") from e
        if mode == "fallback":
            print("[build] 警告：keylib 现场编译不可得，退化为预制件锚点补丁"
                  "（件内保留锚点标记，保护面降级——PROTECTION_ROADMAP §3.3）")
        try:
            kl = KeyLib(dll_path)              # 加载健全性检查（缺失/坏 PE 早炸）
        except KeyLibError as e:
            raise BuildError(str(e)) from e
        # pyc 定位须用运行时解释器的 tag（_zip_lib 同款）——打包机解释器的
        # cache_from_source 可能产出不同 magic tag 名
        pyc_tag = "cpython-" + "".join(c for c in python_dll if c.isdigit())
        code_key_id = _encrypt_app_tree_inner(stage_app, kl, k_app, pyc_tag)
        # ★期1 S2★ 解密器自身密文化（同一 kl/同一 K；applocal 引导 blob 独立
        # 于 app/ 清单，壳侧 pk_x4 按固定 mid 定位）
        _encrypt_applocal_boot(stage, kl, k_app, python_exe, python_dll)
        return code_key_id
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _encrypt_applocal_boot(stage: str, kl: KeyLib, key: bytes,
                           python_exe: str | None, python_dll: str) -> None:
    """★期1 S2★ applocal 解密器密文化——解密根出 Python 明文面（§5.6）。

    双源分支（★P0★ 收拢后形态变化）：
    - `_codekey.pyc`（收拢后）：_compile_flat_tree 已产出的 flat UNCHECKED_HASH
      pyc，直读剥 16 字节头 = marshal 载荷；
    - `_codekey.py`（android / 未收拢形态）：快照解释器单文件现编译（原路径）。
    → pk_x1(K, APPLOCAL_BOOT_MID) 加密 → 回验闸（解密回读一致 + marshal 载荷
    为 code object，纪律同 app/ 加密）→ 落 site-packages/applocal/<blob_name(mid)>
    → **两个明文形态都删**（flat pyc 同样可离线反编译，marshal 残留即明文面）。
    运行期：壳调 keylib pk_x4 定位并解密（停在 marshal.loads 之前）→ 壳 C 层
    marshal/exec 注入 sys.modules。mid/blob 名公式与 key.c 逐位一致（k_m1/k_m2
    偏置拼装 + sha256），漂移由 test_keylib blob_name 对拍拦截。
    明文包（code_encryption=false）不走本函数——壳侧 pk_x4 NOBLOB 静默跳过，
    Python 侧常规 wheel 装入的明文 _codekey 照常工作（双形态兼容）。
    """
    sp_applocal = None                          # ★P0★ loose 聚合目录优先，顶层兜底
    for cand in (os.path.join(stage, "site-packages", "loose", "applocal"),
                 os.path.join(stage, "site-packages", "applocal")):
        if os.path.isfile(os.path.join(cand, "_codekey.pyc")) or \
                os.path.isfile(os.path.join(cand, "_codekey.py")):
            sp_applocal = cand
            break
    if sp_applocal is None:
        raise BuildError("applocal 缺 _codekey.py/.pyc（解密器密文化无从进行）——"
                         "applocal wheel 缺失或版本不符，请检查依赖收集")
    src_py = os.path.join(sp_applocal, "_codekey.py")
    src_pyc = os.path.join(sp_applocal, "_codekey.pyc")
    if os.path.isfile(src_pyc):
        with open(src_pyc, "rb") as f:          # ★P0★ 收拢后 flat pyc 直读
            raw = f.read()
    elif os.path.isfile(src_py):
        with tempfile.TemporaryDirectory(prefix="pkapp-ckey-") as td:
            pyc = os.path.join(td, "codekey.pyc")
            _compile_one_pyc(python_exe, python_dll, src_py, pyc,
                             "applocal/_codekey.py")
            with open(pyc, "rb") as f:
                raw = f.read()
    else:
        raise BuildError("applocal 缺 _codekey.py/.pyc（解密器密文化无从进行）——"
                         "applocal wheel 缺失或版本不符，请检查依赖收集")
    if len(raw) <= 16:
        raise BuildError("_codekey pyc 过短（不足 16 字节头）")
    payload = raw[16:]                          # 剥 pyc 头 = marshal 载荷（§5.3）
    try:
        blob = kl.encrypt(key, APPLOCAL_BOOT_MID, payload)
    except KeyLibError as e:
        raise BuildError(f"_codekey 加密失败: {e}") from e
    # 回验闸：GCM 打开 + marshal 载荷合法，才允许删明文（顺序硬约束同 app/）
    try:
        back = kl.decrypt(APPLOCAL_BOOT_MID, blob)
    except KeyLibError as e:
        raise BuildError(f"_codekey 加密回验解密失败: {e}") from e
    if back != payload:
        raise BuildError("_codekey 加密回验不一致（密文与明文不符）")
    try:
        code = marshal.loads(back)
    except Exception as e:
        raise BuildError(f"_codekey 载荷 marshal 校验失败: {e}") from e
    if not isinstance(code, types.CodeType):
        raise BuildError("_codekey 载荷非 code object")
    with open(os.path.join(sp_applocal, blob_name(APPLOCAL_BOOT_MID)), "wb") as f:
        f.write(blob)
    for p in (src_py, src_pyc):                 # ★P0★ 两个明文形态都删（防 marshal 残留）
        if os.path.isfile(p):
            os.remove(p)
    print(f"[build] applocal/_codekey 已密文化（解密根出明文面，"
          f"{len(payload)}B → {blob_name(APPLOCAL_BOOT_MID)}）")


def _encrypt_app_tree_inner(stage_app: str, kl: KeyLib, key: bytes,
                            pyc_tag: str) -> str:
    """加密执行体（kl = K_app 烧件/补丁件；加密走参数 K、回验走内嵌 K）。"""
    mids: list[str] = []
    for rel in walk_files(stage_app):
        if not rel.endswith(".py"):
            continue
        mid = module_id_for(rel)
        src = os.path.join(stage_app, rel.replace("/", os.sep))
        d, base = os.path.split(rel)
        pyc = os.path.join(stage_app, d, "__pycache__", f"{base[:-3]}.{pyc_tag}.pyc")
        if not os.path.isfile(pyc):
            raise BuildError(f"加密缺 pyc（编译步骤未产出）: {rel}")
        with open(pyc, "rb") as f:
            raw = f.read()
        if len(raw) <= 16:
            raise BuildError(f"pyc 过短（不足 16 字节头）: {rel}")
        payload = raw[16:]                       # 剥 pyc 头 = marshal 载荷（§5.3）
        try:
            blob = kl.encrypt(key, mid, payload)
        except KeyLibError as e:
            raise BuildError(f"加密失败: {mid}: {e}") from e
        # 回验闸：GCM 打开 + marshal 载荷合法，才允许删该模块明文
        try:
            back = kl.decrypt(mid, blob)
        except KeyLibError as e:
            raise BuildError(f"加密回验解密失败: {mid}: {e}") from e
        if back != payload:
            raise BuildError(f"加密回验不一致（密文与明文不符）: {mid}")
        try:
            code = marshal.loads(back)
        except Exception as e:
            raise BuildError(f"加密载荷 marshal 校验失败: {mid}: {e}") from e
        if not isinstance(code, types.CodeType):
            raise BuildError(f"加密载荷非 code object: {mid}")
        with open(os.path.join(stage_app, blob_name(mid)), "wb") as f:
            f.write(blob)
        os.remove(src)
        os.remove(pyc)
        mids.append(mid)
    if not mids:
        raise BuildError("app/ 内无 .py 模块（加密无从进行；纯资源 app/ 请关闭 code_encryption）")
    if "app" not in mids:
        raise BuildError("code_encryption 需要 app/__init__.py 根包——加密模式 finder 必须能"
                         "认领 'app' 包本身，namespace 包（缺根 __init__.py）不受支持")
    # 加密清单（§6.1 step3）：AAD 身份 app.__index__，落盘 app/index.enc；
    # finder 以它做成员资格判定（§7.1），避免误吞用户侧同名顶层模块
    index_payload = build_index_payload(sorted(mids))
    try:
        iblob = kl.encrypt(key, INDEX_MODULE_ID, index_payload)
        if kl.decrypt(INDEX_MODULE_ID, iblob) != index_payload:
            raise BuildError("加密清单回验不一致")
    except KeyLibError as e:
        raise BuildError(f"加密清单失败: {e}") from e
    with open(os.path.join(stage_app, INDEX_FILE_NAME), "wb") as f:
        f.write(iblob)
    # 删明文闸（§6.1 step4）：staging app/ 内不允许残留任何 .py/.pyc
    leftovers = [rel for rel in walk_files(stage_app)
                 if rel.endswith((".py", ".pyc"))]
    if leftovers:
        raise BuildError("删明文闸失败（staging 仍残留明文）: " + ", ".join(leftovers[:8]))
    for dirpath, dirnames, _filenames in os.walk(stage_app, topdown=False):
        if os.path.basename(dirpath) == "__pycache__" and not os.listdir(dirpath):
            os.rmdir(dirpath)
    return kl.key_id()
