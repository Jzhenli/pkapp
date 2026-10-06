"""keylib 契约测试（CODE_PROTECTION_DESIGN.md §5 / 阶段1 验收）。

参照实现 = cryptography（OpenSSL）AESGCM + 标准库 hmac：pk_x1 产物与
Python 侧按同规格重组的 blob 必须逐字节一致——等价于对 C 内 GCM/HMAC 全链做
已知向量验证（nonce = HMAC-SHA256(K, module_id)[:12]、AAD = module_id、
tag = GCM 认证标签）。解密/补丁链路用补丁后的 dll 副本驱动（package 闸门同款）。
"""
from __future__ import annotations

import ctypes
import hashlib
import hmac
import importlib
import json
import marshal
import os
import shutil
import sys
import types

import pytest

from pkapp.packager import assemble, keylib
from pkapp.packager.keylib import KeyLib, KeyLibError

_DLL = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), "keylib", "build", "pkapp_key.dll")

# 运行解释器同 minor 的 runtime dll 名——pyc tag（cache_from_source）与其派生 tag
# 自洽，任何解释器版本下加密链测试均可跑（不硬绑 3.12）
_RUNTIME_DLL = f"python{sys.version_info.major}{sys.version_info.minor}.dll"

pytestmark = pytest.mark.skipif(not os.path.isfile(_DLL),
                                reason="keylib/build/pkapp_key.dll 未编译（先跑 keylib/build.bat）")


@pytest.fixture(scope="module")
def lib() -> KeyLib:
    return KeyLib(_DLL)


def _patched_copy(tmp_path, key: bytes) -> str:
    out = str(tmp_path / "pkapp_key.patched.dll")
    keylib.patch_dll(_DLL, out, key)
    return out


def _reference_blob(key: bytes, module_id: str, payload: bytes) -> bytes:
    """按设计规格（§5.3/§5.4③）用参照实现重组 blob——与 C 产物逐字节比对。"""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = hmac.new(key, module_id.encode("utf-8")
                     + hashlib.sha256(payload).digest()[:16],
                     hashlib.sha256).digest()[:12]
    ct = AESGCM(key).encrypt(nonce, payload, module_id.encode("utf-8"))
    return b"PKK1" + bytes([1]) + nonce + ct


def test_encrypt_matches_reference(lib):
    """C 加密产物 ≡ 参照实现（HMAC nonce + AES-256-GCM + AAD，逐字节）。"""
    key = bytes(range(32))
    for module_id, payload in (
        ("app", b""),
        ("app.main", b"hello world"),
        ("app.sub.pkg.mod", bytes(range(256)) * 7),   # 非对齐长度 + 多块
        ("app.__index__", b"app\napp.main\n"),
    ):
        blob = lib.encrypt(key, module_id, payload)
        assert blob[:4] == b"PKK1" and blob[4] == 1
        assert blob == _reference_blob(key, module_id, payload)
        assert len(blob) == len(payload) + keylib.BLOB_OVERHEAD


def test_encrypt_deterministic_g5(lib):
    """G5：同 K + 同 module_id + 同载荷 → 密文逐字节稳定（确定性 nonce）。"""
    key = hashlib.sha256(b"k").digest()
    a = lib.encrypt(key, "app.main", b"payload")
    b = lib.encrypt(key, "app.main", b"payload")
    c = lib.encrypt(key, "app.other", b"payload")
    assert a == b
    assert a != c                       # 模块名绑定（nonce/AAD 双通道）


def test_patch_and_roundtrip(lib, tmp_path):
    """补丁契约：K 内嵌后 decrypt 用内嵌态打开（运行期形态），key_id 配对。"""
    key = hashlib.sha256(b"project-key").digest()
    patched = _patched_copy(tmp_path, key)
    p2 = KeyLib(patched)
    payload = b"marshal payload \x00\x01 here"
    blob = p2.encrypt(key, "app.main", payload)     # encrypt 恒走参数 key
    assert p2.decrypt("app.main", blob) == payload  # decrypt 走内嵌 K（§5.2）
    assert p2.key_id() == keylib.key_id_hex(key)    # SHA256(K)[:16] hex = 32 字符
    assert len(p2.key_id()) == 32


def test_patch_gate_detects_wrong_key(lib, tmp_path):
    """跨 key 拒绝：A 钥加密的 blob 在 B 钥补丁件上解不开（package 闸门语义）。"""
    ka = hashlib.sha256(b"A").digest()
    kb = hashlib.sha256(b"B").digest()
    blob = lib.encrypt(ka, "app.main", b"x")
    p2 = KeyLib(_patched_copy(tmp_path, kb))
    with pytest.raises(KeyLibError):
        p2.decrypt("app.main", blob)


def test_tamper_detected(lib, tmp_path):
    """损坏检测：密文任一字节翻转 → GCM 认证失败（code_decrypt diag 语义）。"""
    key = hashlib.sha256(b"t").digest()
    blob = bytearray(lib.encrypt(key, "app.main", b"payload bytes"))
    blob[20] ^= 0x01
    p2 = KeyLib(_patched_copy(tmp_path, key))
    with pytest.raises(KeyLibError):
        p2.decrypt("app.main", bytes(blob))


def test_aad_mismatch_rejected(lib, tmp_path):
    """AAD 模块名绑定：换名解密必败（防包内换位，§5.2）。"""
    key = hashlib.sha256(b"aad").digest()
    blob = lib.encrypt(key, "app.main", b"payload")
    p2 = KeyLib(_patched_copy(tmp_path, key))
    with pytest.raises(KeyLibError):
        p2.decrypt("app.other", blob)


def test_anchor_unique_in_dll():
    """补丁锚点在分发件内必须唯一出现（package patch_dll 的定位前提）。"""
    with open(_DLL, "rb") as f:
        data = f.read()
    assert data.count(keylib.ANCHOR) == 1


def test_seed_not_in_dll():
    """★2026-10 防逆向强化★：seed 真值（Python 侧契约常量）在 dll 内 0 命中——
    件内只存包裹态（SEED_STORED = seed ⊕ SHA256(k_s1 ‖ k_s2)，字节形态存在、
    hex 串形态不存在）。ANCHOR 明文是补丁定位器不属秘密（唯一性契约见上例）；
    本用例 grep 防回退：有人把 seed 真值写回 key.c/key.h 即红。"""
    with open(_DLL, "rb") as f:
        data = f.read()
    seed = keylib._hex_to_32(keylib.MASK_SEED_HEX)
    assert data.count(seed) == 0                       # 真值字节 0 命中
    assert data.count(seed.hex().encode("ascii")) == 0  # 真值 hex ASCII 0 命中
    # 包裹态在件内但只以字节数组形态：hex 字符串 0 命中
    stored_hex = b"3fbedf84170b37c06680f4b77c98b79cc5bd7d58059119b562e79d956a6b0736"
    assert data.count(stored_hex) == 0
    # 契约有效性：Python 侧镜像 mask 与件内包裹态自洽（unwrap 等价可逆）
    k1 = hashlib.sha256(
        bytes.fromhex("9e3c41d7a8f25b60c1e94a73d68f0b52")
        + bytes.fromhex("47a1c85e03d69bf27c5a41e9830b7d64fa2519ce6b803d47")).digest()
    assert bytes(s ^ k for s, k in zip(seed, k1)) == bytes.fromhex(stored_hex.decode())
    assert data.count(bytes.fromhex(stored_hex.decode())) == 1   # 字节形态恰 1


def test_exports_minimal():
    """★2026-10 防逆向强化★：导出面 = {pk_x1, pk_x2, pk_x3}（语义名已移除）——
    新名齐备由 KeyLib 构造实证（缺任一即 AttributeError）；旧语义名残留在此
    0 命中拦截（无意义化是单向契约，PE 全表解析过重）。"""
    lib = KeyLib(_DLL)
    assert len(lib.key_id()) == 32
    raw = ctypes.CDLL(_DLL)     # 独立逐名探测：残留旧导出名即红
    for old in ("pkapp_encrypt", "pkapp_decrypt", "pkapp_key_id"):
        assert not hasattr(raw, old)


def test_generic_key_id_matches_python_mirror(lib):
    """掩码镜像校验：通用件 key_id ≡ Python 侧 ANCHOR^_MASK（mask 派生）推导。"""
    k = bytes(a ^ b for a, b in zip(keylib.ANCHOR, keylib._MASK))
    assert lib.key_id() == keylib.key_id_hex(k)


def test_patch_anchor_not_found(tmp_path):
    """非 key-holder 件（无锚点）→ 定位失败报错（模式 B 语义：不补丁）。"""
    fake = tmp_path / "fake.dll"
    fake.write_bytes(b"\x00" * 64)
    with pytest.raises(KeyLibError):
        keylib.patch_dll(str(fake), str(tmp_path / "out.dll"), b"\x01" * 32)


# ---------------------------------------------------------------- 纯 Python 面
def test_module_id_for():
    assert keylib.module_id_for("main.py") == "app.main"
    assert keylib.module_id_for("__init__.py") == "app"
    assert keylib.module_id_for("sub/x.py") == "app.sub.x"
    assert keylib.module_id_for("sub/__init__.py") == "app.sub"
    assert keylib.module_id_for("a/b/c/__init__.py") == "app.a.b.c"


def test_blob_name():
    assert keylib.blob_name("app.main") == \
        hashlib.sha256(b"app.main").hexdigest() + ".enc"


def test_ensure_obf_key(tmp_path):
    """★§13.3③ S5★ 混淆密钥：32 字节、幂等（已有即读）、.pkapp/ gitignore 覆盖。"""
    key = keylib.ensure_obf_key(str(tmp_path))
    assert len(key) == 32
    assert (tmp_path / ".pkapp" / "obf.key").is_file()
    assert keylib.ensure_obf_key(str(tmp_path)) == key          # 幂等
    gi = tmp_path / ".gitignore"
    assert gi.is_file() and ".pkapp/" in gi.read_text(encoding="utf-8")


def test_ensure_obf_key_rejects_corrupt(tmp_path):
    kp = tmp_path / ".pkapp" / "obf.key"
    kp.parent.mkdir(parents=True)
    kp.write_text("zz", encoding="ascii")
    with pytest.raises(KeyLibError):
        keylib.ensure_obf_key(str(tmp_path))


# ------------------------------------------------- ★档位1★ K 派生化（PROTECTION_ROADMAP §3）
_APP = "demo"     # 测试 app_id（HKDF info；与 _stage_keylib/_encrypt_app_tree 同源）


def _set_master(monkeypatch, name: str = "stage-master") -> bytes:
    """固定 K_master 注入 env（resolve_master_key 首选源；测试与家目录零接触）。"""
    master = hashlib.sha256(name.encode("ascii")).digest()
    monkeypatch.setenv("PKAPP_MASTER_KEY", master.hex())
    return master


def test_resolve_master_key_env_overrides(monkeypatch):
    """env PKAPP_MASTER_KEY 恒优先（多机同源 master 的覆盖入口）。"""
    master = _set_master(monkeypatch)
    got, generated = keylib.resolve_master_key()
    assert got == master and not generated


def test_resolve_master_key_file_keygen(tmp_path, monkeypatch):
    """文件托管：缺失即 keygen（幂等复读）；路径由 PKAPP_MASTER_KEY_FILE 定向 tmp
    （conftest autouse 已定向——POSIX 600 权限位由 resolve 写入侧保证）。"""
    monkeypatch.delenv("PKAPP_MASTER_KEY", raising=False)
    path = tmp_path / "master.key"
    monkeypatch.setenv("PKAPP_MASTER_KEY_FILE", str(path))
    first, generated = keylib.resolve_master_key()
    assert generated and len(first) == 32 and path.is_file()
    assert path.read_text(encoding="ascii") == first.hex()
    second, generated2 = keylib.resolve_master_key()
    assert not generated2 and second == first                   # 幂等


def test_resolve_master_key_create_false_fails_fast(tmp_path, monkeypatch):
    """package 期纪律（create=False）：master 缺失 → 报错且绝不静默 keygen
    （新 master 派生的 K 必不与既有 spk 配对——掩盖密钥丢失只会更糟）。"""
    monkeypatch.delenv("PKAPP_MASTER_KEY", raising=False)
    monkeypatch.setenv("PKAPP_MASTER_KEY_FILE", str(tmp_path / "absent.key"))
    with pytest.raises(KeyLibError, match="K_master 缺失"):
        keylib.resolve_master_key(create=False)
    assert not (tmp_path / "absent.key").exists()


def test_resolve_master_key_rejects_corrupt(tmp_path, monkeypatch):
    monkeypatch.delenv("PKAPP_MASTER_KEY", raising=False)
    path = tmp_path / "master.key"
    path.write_text("zz", encoding="ascii")
    monkeypatch.setenv("PKAPP_MASTER_KEY_FILE", str(path))
    with pytest.raises(KeyLibError):
        keylib.resolve_master_key(create=False)


def _hkdf_rfc5869(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """RFC 5869 标准 HKDF-SHA256 参照实现（完整 extract+expand，无 salt 下限——
    官方向量 salt 均 13B 可直接喂）。derive_k_app 是它的 salt≥16B、info 固定
    域分离标签的单块特例。"""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


def test_hkdf_reference_impl_matches_rfc5869_vectors():
    """参照实现先被 RFC 5869 三个官方向量（A.1–A.3）钉死——后续对拍以此为锚。"""
    assert _hkdf_rfc5869(
        b"\x0b" * 22, bytes.fromhex("000102030405060708090a0b0c"),
        bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")) == bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf")
    # TC2：长输入（IKM/salt/info 各 80B 递增序列），L=82 → expand 多块路径全覆盖
    assert _hkdf_rfc5869(
        bytes(range(0x50)), bytes(range(0x60, 0xb0)),
        bytes(range(0xb0, 0x100)), length=82) == bytes.fromhex(
        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
        "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
        "cc30c58179ec3e87c14c01d5c1f3434f1d87")
    assert _hkdf_rfc5869(b"\x0b" * 22, b"", b"") == bytes.fromhex(
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d")


def test_derive_k_app_matches_reference_impl():
    """derive_k_app ≡ 参照实现（被官方向量钉死）的单块特例：默认档 + 自定 ≥16B
    salt 双对拍，info = 域分离标签 b"pkapp/app\\x00" ‖ app_id（与实现逐字节同源）。"""
    master = hashlib.sha256(b"m").digest()
    assert keylib.derive_k_app(master, "demo") == _hkdf_rfc5869(
        master, bytes.fromhex(keylib.DEFAULT_SALT_HEX), b"pkapp/app\x00demo")
    salt32 = bytes(range(32))      # RFC 官方向量 salt 均 13B 吃不到 API 下限，经参照实现传递
    assert keylib.derive_k_app(master, "demo", salt32) == _hkdf_rfc5869(
        master, salt32, b"pkapp/app\x00demo")


def test_derive_k_app_deterministic_and_isolated():
    """G5：同 (master, app_id, salt) 恒同 K；app_id 横向隔离（§1.1）；salt 参与
    派生；非法入参拒绝。"""
    master = hashlib.sha256(b"m").digest()
    assert keylib.derive_k_app(master, _APP) == keylib.derive_k_app(master, _APP)
    assert keylib.derive_k_app(master, _APP) != keylib.derive_k_app(master, "other")
    assert keylib.derive_k_app(master, _APP) != \
        keylib.derive_k_app(master, _APP, salt=b"\x01" * 16)
    with pytest.raises(KeyLibError):
        keylib.derive_k_app(b"short", _APP)
    with pytest.raises(KeyLibError):
        keylib.derive_k_app(master, "")
    with pytest.raises(KeyLibError):
        keylib.derive_k_app(master, _APP, salt=b"\x01" * 8)   # salt <16B


def test_generate_kdata_c_generic_matches_repo_kdata():
    """通用件形态：generate_kdata_c(None) ≡ 仓库 kdata.c 锚点初值（逐字节）——
    build.bat 产物与现场生成器同源（锚点补丁退化路径的定位前提）。"""
    import re as _re
    repo = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)))), "keylib", "src", "kdata.c")
    text = open(repo, encoding="utf-8").read()
    inited = _re.search(r"k_stored\[32\]\s*=\s*\{(.*?)\}", text, _re.S).group(1)
    assert bytes(int(x, 16) for x in _re.findall(r"0x[0-9a-fA-F]{2}", inited)) \
        == keylib.ANCHOR
    gen = keylib.generate_kdata_c(None)
    assert "uint8_t k_stored[32]" in gen
    gen_bytes = bytes(int(x, 16) for x in _re.findall(
        r"0x[0-9a-fA-F]{2}", gen.split("=", 1)[1]))
    assert gen_bytes == keylib.ANCHOR


def test_generate_kdata_c_wrapped_form():
    """per-app 形态：k_stored = K_app ^ _MASK（key.c unwrap 运行期反向同式）；
    异或回卷还原 K_app；K 的 hex 串形态不存在（strings 捞不到）。"""
    import re as _re
    k_app = hashlib.sha256(b"kdata").digest()
    src = keylib.generate_kdata_c(k_app)
    arr = _re.search(r"k_stored\[32\]\s*=\s*\{(.*?)\}", src, _re.S).group(1)
    stored = bytes(int(x, 16) for x in _re.findall(r"0x[0-9a-fA-F]{2}", arr))
    assert stored == bytes(k ^ m for k, m in zip(k_app, keylib._MASK))
    assert bytes(s ^ m for s, m in zip(stored, keylib._MASK)) == k_app
    assert k_app.hex().encode("ascii") not in src.encode("utf-8")
    assert stored != keylib.ANCHOR                       # 非通用件形态


# ---------------------------------------------------------------- 阶段2a：构建链集成
def _compile_stage_app(stage_app):
    """app/ 树编译 checked-hash pyc（tag 跟随运行解释器，与 _RUNTIME_DLL 派生
    tag 一致——assemble _encrypt_app_tree 的定位前提）。"""
    import py_compile
    from importlib.util import cache_from_source

    for dirpath, _dns, fns in os.walk(stage_app):
        for fn in fns:
            if not fn.endswith(".py"):
                continue
            src = os.path.join(dirpath, fn)
            rel = os.path.relpath(src, stage_app).replace(os.sep, "/")
            pyc = cache_from_source(src)
            os.makedirs(os.path.dirname(pyc), exist_ok=True)
            py_compile.compile(src, cfile=pyc, dfile=rel, doraise=True, quiet=2,
                               invalidation_mode=py_compile.PycInvalidationMode.CHECKED_HASH)


def _make_stage_app(tmp_path):
    """staging app/ 树：根包 + main + 子包 + 非 .py 资源（Q2 保留位）。"""
    app = tmp_path / "app"
    (app / "sub").mkdir(parents=True)
    (app / "__init__.py").write_text("APP = 1\n", encoding="utf-8")
    (app / "main.py").write_text("from .sub import x\nVALUE = x.N\n", encoding="utf-8")
    (app / "sub" / "__init__.py").write_text("", encoding="utf-8")
    (app / "sub" / "x.py").write_text("N = 42\n", encoding="utf-8")
    (app / "data.bin").write_bytes(b"\x00\x01plaintext-resource")   # 非 .py 明文保留
    _compile_stage_app(str(app))
    # ★期1 S2★ _codekey 密文化的输入位（staging site-packages/applocal；
    # 最小合法源码即可——回验只校验 marshal 载荷合法性，不关心内容）
    ck = tmp_path / "site-packages" / "applocal"
    ck.mkdir(parents=True)
    (ck / "_codekey.py").write_text(
        '"""pkapp code-key boot (stage stub)."""\nSTUB = 1\n', encoding="utf-8")
    return app


def test_encrypt_app_tree_stage_contract(lib, tmp_path, monkeypatch):
    """§6.1 + ★档位1★ 全契约：master→K_app 现场派生 → blob 落盘 ≡ 参照实现 →
    索引 → 删明文 → 资源保留；件 key_id ≡ derive 镜像；K 不持久化。"""
    from pkapp.packager.assemble import _encrypt_app_tree

    app = tmp_path / "app"
    _make_stage_app(tmp_path)
    master = _set_master(monkeypatch)
    k_app = keylib.derive_k_app(master, _APP)

    kid = _encrypt_app_tree(str(tmp_path), None, _RUNTIME_DLL, _APP)
    assert kid == keylib.key_id_hex(k_app)             # manifest code_key_id 配对值

    # 逐 blob：K_app 内嵌件（运行期形态）解密 → marshal 载荷合法 + co_filename 归一
    (tmp_path / "patchwork").mkdir()
    patched = KeyLib(_patched_copy(tmp_path / "patchwork", k_app))
    rel_of = {"app": "__init__.py", "app.main": "main.py",
              "app.sub": "sub/__init__.py", "app.sub.x": "sub/x.py"}
    for mid, rel in rel_of.items():
        bp = app / keylib.blob_name(mid)
        assert bp.is_file()
        blob = bp.read_bytes()
        assert blob[:4] == b"PKK1" and len(blob) >= keylib.BLOB_OVERHEAD
        code = marshal.loads(patched.decrypt(mid, blob))
        assert isinstance(code, types.CodeType)
        assert code.co_filename == rel
    index_blob = (app / "index.enc").read_bytes()
    payload = patched.decrypt("app.__index__", index_blob)   # AAD 身份开清单
    assert payload.decode("utf-8") == \
        "PKIDX1\nM app\nM app.main\nM app.sub\nM app.sub.x\n"
    # 删明文闸：无 .py/.pyc 残留，__pycache__ 清空，资源保留（Q2）
    left = [dp for dp in _walk_all(str(app))
            if dp.endswith((".py", ".pyc"))]
    assert left == []
    assert (app / "data.bin").read_bytes() == b"\x00\x01plaintext-resource"
    assert not any(os.path.basename(dp) == "__pycache__" and os.listdir(dp)
                   for dp, _dn, _fn in os.walk(str(app)))
    # ★期1 S2★ _codekey 密文化：明文已删、引导 blob 落位、补丁件可开
    sp_ck = tmp_path / "site-packages" / "applocal"
    ck_blob = sp_ck / keylib.blob_name(keylib.APPLOCAL_BOOT_MID)
    assert ck_blob.is_file()
    assert not (sp_ck / "_codekey.py").exists()
    ck_code = marshal.loads(patched.decrypt(keylib.APPLOCAL_BOOT_MID,
                                            ck_blob.read_bytes()))
    assert isinstance(ck_code, types.CodeType)
    assert ck_code.co_filename == "applocal/_codekey.py"
    # ★档位1★ K 不持久化：派生全程零落盘（master 文件未被 keygen）
    assert not (tmp_path / "master.key").exists()


def _walk_all(root):
    out = []
    for dp, _dn, fns in os.walk(root):
        for fn in fns:
            out.append(os.path.join(dp, fn))
    return out


def test_encrypt_app_tree_keylib_unavailable(tmp_path, monkeypatch):
    """构建期判定（§8）：keylib 件产出不可得（编译失败 × 预制件缺失）→ 构建
    报错，不做静默降级。"""
    from pkapp.packager import assemble

    _make_stage_app(tmp_path)
    _set_master(monkeypatch)

    def boom(*_a, **_k):
        raise KeyLibError("key-holder 件缺失")

    monkeypatch.setattr(assemble, "produce_keylib", boom)
    with pytest.raises(assemble.BuildError, match="key-holder"):
        assemble._encrypt_app_tree(str(tmp_path), None, _RUNTIME_DLL, _APP)


def test_appspec_code_encryption_flag(tmp_path):
    """Q4：开关在 [app] 段，缺省 false（G6）。"""
    from pkapp.appspec import load

    root = tmp_path
    base = ('[app]\nname = "demo"\nversion = "0.1.0"\n'
            'entry = "app.main:app"\nmin_app_version = "0.1.0"\n')
    (root / "pkapp.toml").write_text(base, encoding="utf-8")
    assert load(str(root / "pkapp.toml")).code_encryption is False
    (root / "pkapp.toml").write_text(
        base.replace('[app]\n', '[app]\ncode_encryption = true\n'), encoding="utf-8")
    assert load(str(root / "pkapp.toml")).code_encryption is True


def test_appspec_code_obfuscation_flag(tmp_path):
    """★§13 混淆叠加层★：开关在 [app] 段，缺省 false（G6 零回归）。"""
    from pkapp.appspec import load

    root = tmp_path
    base = ('[app]\nname = "demo"\nversion = "0.1.0"\n'
            'entry = "app.main:app"\nmin_app_version = "0.1.0"\n')
    (root / "pkapp.toml").write_text(base, encoding="utf-8")
    assert load(str(root / "pkapp.toml")).code_obfuscation is False
    (root / "pkapp.toml").write_text(
        base.replace('[app]\n', '[app]\ncode_obfuscation = true\n'), encoding="utf-8")
    assert load(str(root / "pkapp.toml")).code_obfuscation is True


def test_manifest_ext_key_code_key_id():
    """§7.3：code_key_id 为可选扩展键——明文构建无此键（G2 不约束），加密构建
    写入且被签名正文覆盖（canonical_bytes 保留）。"""
    from pkapp.packager import manifest as mf

    fields = {k: "v" for k in mf.KEYS}
    plain = mf.render(fields)
    assert "code_key_id" not in plain
    fields["code_key_id"] = "a" * 32
    text = mf.render(fields)
    assert f"code_key_id = {'a' * 32}" in text
    assert mf.parse(text)["code_key_id"] == "a" * 32
    assert "code_key_id" in mf.canonical_bytes(text).decode("utf-8")


def test_appspec_per_build_salt_flag(tmp_path):
    """★档位1 §3.2 R-2★：per-build salt 档为 [app] 显式 opt-in，缺省 false
    （默认档 = 固定 salt 常量，G5 跨构建稳定保留）。"""
    from pkapp.appspec import load

    root = tmp_path
    base = ('[app]\nname = "demo"\nversion = "0.1.0"\n'
            'entry = "app.main:app"\nmin_app_version = "0.1.0"\n')
    (root / "pkapp.toml").write_text(base, encoding="utf-8")
    assert load(str(root / "pkapp.toml")).per_build_salt is False
    (root / "pkapp.toml").write_text(
        base.replace('[app]\n', '[app]\nper_build_salt = true\n'), encoding="utf-8")
    assert load(str(root / "pkapp.toml")).per_build_salt is True


def test_manifest_ext_key_code_salt():
    """★档位1★ code_salt 可选扩展键：默认档无此键；per-build 档写入且被签名
    正文覆盖（canonical_bytes 保留；壳 C 解析器按未知键忽略）。"""
    from pkapp.packager import manifest as mf

    fields = {k: "v" for k in mf.KEYS}
    assert "code_salt" not in mf.render(fields)
    fields["code_salt"] = "ab" * 32
    text = mf.render(fields)
    assert f"code_salt = {'ab' * 32}" in text
    assert mf.parse(text)["code_salt"] == "ab" * 32
    assert "code_salt" in mf.canonical_bytes(text).decode("utf-8")


# ---------------------------------------------------------------- 阶段2b：package 派生与闸门
def test_stage_keylib_derives_and_gates(tmp_path, monkeypatch):
    """★档位1★ 正向：master 派生 K_app → 现场产出专属件 → key_id ≡ manifest
    配对值；产出件按运行期形态打开 K_app 加密的 blob。"""
    from pkapp.commands.package import _stage_keylib

    monkeypatch.delenv("PKAPP_KEYLIB", raising=False)
    master = _set_master(monkeypatch)
    k_app = keylib.derive_k_app(master, _APP)
    stage = str(tmp_path / "stage")
    os.makedirs(stage)
    assert _stage_keylib(stage, keylib.key_id_hex(k_app), app_id=_APP) == 0
    out = os.path.join(stage, "pkapp_key.dll")
    assert os.path.isfile(out)
    kl = KeyLib(out)
    assert kl.key_id() == keylib.key_id_hex(k_app)
    blob = kl.encrypt(k_app, "app.main", b"payload")       # encrypt 恒走参数 K
    assert kl.decrypt("app.main", blob) == b"payload"      # decrypt 走内嵌 K（运行期同构）
    # 分发原件零触碰（编译/补丁都只写 staging 副本）
    assert open(out, "rb").read() != open(_DLL, "rb").read()


def test_stage_keylib_salt_roundtrip(tmp_path, monkeypatch):
    """per_build_salt 档：manifest code_salt hex → 同 master 同 salt 派生同 K；
    丢 salt（按默认档派生）→ 异 K 被闸门拦下。"""
    from pkapp.commands.package import _stage_keylib

    monkeypatch.delenv("PKAPP_KEYLIB", raising=False)
    master = _set_master(monkeypatch)
    salt = os.urandom(32)
    k_app = keylib.derive_k_app(master, _APP, salt)
    stage = str(tmp_path / "stage")
    os.makedirs(stage)
    assert _stage_keylib(stage, keylib.key_id_hex(k_app), app_id=_APP,
                         salt_hex=salt.hex()) == 0
    stage2 = str(tmp_path / "stage2")
    os.makedirs(stage2)
    assert _stage_keylib(stage2, keylib.key_id_hex(k_app), app_id=_APP) == 2


def test_stage_keylib_rejects_corrupt_salt(tmp_path, monkeypatch):
    """★review 修复回归★：manifest code_salt 损坏（非法 hex）→ 闸门 rc=2（打印
    原因），不 traceback 崩溃——与其余失败路径同收敛（保留 staging 现场）。"""
    from pkapp.commands.package import _stage_keylib

    _set_master(monkeypatch)
    stage = str(tmp_path / "stage")
    os.makedirs(stage)
    assert _stage_keylib(stage, "0" * 32, app_id=_APP, salt_hex="not-hex!") == 2


def test_stage_keylib_rejects_mismatched_key(tmp_path, monkeypatch):
    """跨 key 闸门：manifest code_key_id 与 master 派生值不配对（master 更换/
    丢失重生成/新旧混装）→ package 拒绝（返回 2），失败保留 staging 现场。"""
    from pkapp.commands.package import _stage_keylib

    monkeypatch.delenv("PKAPP_KEYLIB", raising=False)
    _set_master(monkeypatch)
    kb = hashlib.sha256(b"B").digest()
    stage = str(tmp_path / "stage")
    os.makedirs(stage)
    assert _stage_keylib(stage, keylib.key_id_hex(kb), app_id=_APP) == 2
    assert os.path.isfile(os.path.join(stage, "pkapp_key.dll"))


def test_stage_keylib_missing_master(tmp_path, monkeypatch):
    """spk 已加密而 K_master 缺失 = 不可交付：报错且不 keygen（新 master 必不
    配对，静默生成只会掩盖密钥丢失）。"""
    from pkapp.commands.package import _stage_keylib

    monkeypatch.delenv("PKAPP_KEYLIB", raising=False)
    monkeypatch.delenv("PKAPP_MASTER_KEY", raising=False)   # 覆盖 autouse 隔离位
    stage = str(tmp_path / "stage")
    os.makedirs(stage)
    assert _stage_keylib(stage, "0" * 32, app_id=_APP) == 2
    assert not os.path.isfile(os.path.join(tmp_path, "master.key"))  # 未静默 keygen


def test_stage_keylib_mode_b_no_patch(tmp_path, monkeypatch):
    """模式 B（PKAPP_KEYLIB 自管件，K 编译期内嵌）：不补丁仅落位，闸门仍生效。"""
    from pkapp.commands.package import _stage_keylib

    master = _set_master(monkeypatch)
    k_app = keylib.derive_k_app(master, _APP)
    own = tmp_path / "own" / "pkapp_key.dll"
    own.parent.mkdir(parents=True)
    keylib.patch_dll(_DLL, str(own), k_app)
    before = own.read_bytes()
    monkeypatch.setenv("PKAPP_KEYLIB", str(own))
    stage = str(tmp_path / "stage")
    os.makedirs(stage)
    assert _stage_keylib(stage, keylib.key_id_hex(k_app), app_id=_APP) == 0
    assert (tmp_path / "stage" / "pkapp_key.dll").read_bytes() == before  # 逐字节未改写
    # 自管件 key_id 与 manifest 不符同样被闸门拦下
    stage2 = str(tmp_path / "stage2")
    os.makedirs(stage2)
    assert _stage_keylib(stage2, keylib.key_id_hex(hashlib.sha256(b"X").digest()),
                         app_id=_APP) == 2


# ---------------------------------------------------------------- 阶段2b-android：异平台件落位
def test_stage_keylib_android_patches_and_gates(tmp_path, monkeypatch,
                                                android_keylib_so):
    """android .so（构建机无法 dlopen ELF）：强制现场编译失手走锚点补丁（conftest
    fixture），key_id 闸门用 Python 镜像 key_id_hex(K_app) 比对（ctypes 实测仅
    windows 平台件可用）。"""
    from pkapp.commands.package import _stage_keylib

    monkeypatch.delenv("PKAPP_KEYLIB", raising=False)
    master = _set_master(monkeypatch)
    k_app = keylib.derive_k_app(master, _APP)
    stage = str(tmp_path / "stage")
    os.makedirs(stage)
    assert _stage_keylib(stage, keylib.key_id_hex(k_app), "android",
                         app_id=_APP) == 0
    out = os.path.join(stage, "lib_pkapp_key.so")
    assert os.path.isfile(out)
    with open(out, "rb") as f:
        data = f.read()
    with open(android_keylib_so, "rb") as f:
        src = f.read()
    i = src.index(keylib.ANCHOR)
    assert keylib.ANCHOR not in data                     # 锚点已改写（不再含原值）
    assert data[i:i + 32] == bytes(k ^ m for k, m in zip(k_app, keylib._MASK))
    assert data[:i] == src[:i] and data[i + 32:] == src[i + 32:]   # 其余字节零扰动


def test_stage_keylib_android_rejects_mismatched_key(tmp_path, monkeypatch,
                                                     android_keylib_so):
    """android 闸门负向：manifest code_key_id 与 master 派生值不配对 → rc=2
    （补丁件保留 staging 现场供排查，同 windows 语义）。"""
    from pkapp.commands.package import _stage_keylib

    monkeypatch.delenv("PKAPP_KEYLIB", raising=False)
    _set_master(monkeypatch)
    kb = hashlib.sha256(b"B-and").digest()
    stage = str(tmp_path / "stage")
    os.makedirs(stage)
    assert _stage_keylib(stage, keylib.key_id_hex(kb), "android",
                         app_id=_APP) == 2
    assert os.path.isfile(os.path.join(stage, "lib_pkapp_key.so"))


# ---------------------------------------------------------------- 阶段2c：applocal 运行期 finder（跨包契约）
_APPLOCAL = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), "applocal")


def _codekey_mods():
    """按路径引入 applocal（纯 stdlib 包）——构建链 ⇄ 运行期的跨包契约在此对拍。"""
    if _APPLOCAL not in sys.path:
        sys.path.insert(0, _APPLOCAL)
    from applocal import _codekey, _env
    return _codekey, _env


@pytest.fixture()
def finder_clean():
    """防泄漏：finder 持有本次 tmp_path，跨用例残留会污染后续 app.* 导入。"""
    yield
    ck, _env = _codekey_mods()
    sys.meta_path[:] = [f for f in sys.meta_path if not isinstance(f, ck._EncFinder)]
    for n in [n for n in sys.modules if n == "app" or n.startswith("app.")]:
        del sys.modules[n]


@pytest.fixture()
def shell_env(tmp_path, monkeypatch):
    """embedded 运行态 env（applocal/tests 同款契约）：runtime/app 即加密部署位。"""
    ck, _env = _codekey_mods()
    d = tmp_path / "deploy"
    (d / "runtime").mkdir(parents=True)
    vals = {
        "MYAPP_PLATFORM": "windows",
        "MYAPP_DATA_DIR": str(d / "data"),
        "MYAPP_CACHE_DIR": str(d / "cache"),
        "MYAPP_READY_FILE": str(d / "cache" / "ready"),
        "MYAPP_DIAG_FILE": str(d / "cache" / "diag.json"),
        "MYAPP_STATIC_DIR": str(d / "dist"),
        "MYAPP_VERSION": "1.0.0",
        "MYAPP_MANIFEST_PATH": str(d / "runtime" / "manifest"),
    }
    for k, v in vals.items():
        monkeypatch.setenv(k, v)
    for k in ("MYAPP_LOG_DIR", "MYAPP_PORT", "MYAPP_HANDSHAKE_FILE",
              "MYAPP_NATIVE_LIB_DIR", "MYAPP_STRICT_AUTH", "MYAPP_DEV",
              "MYAPP_LAN", "MYAPP_AUTH", "MYAPP_TOKEN"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(_env, "_cfg", None)
    return d


def _write_manifest(base, kid: str):
    (base / "runtime" / "manifest").write_text(
        f"app_version = 1.0.0\npython_dll = python312.dll\nentry = app.main:app\n"
        f"code_key_id = {kid}\n", encoding="utf-8")


def _encrypted_deploy(base, tmp_path, monkeypatch, master: bytes) -> str:
    """把 stage app 加密成运行态部署（blob + index.enc + 明文资源），返回 K_app
    内嵌件路径（运行期形态）。app_id 恒 _APP——与构建侧同源派生。"""
    _make_stage_app(base / "runtime")                    # app/ 树 → <runtime>/app
    monkeypatch.setenv("PKAPP_MASTER_KEY", master.hex())  # 构建侧 master 注入
    from pkapp.packager.assemble import _encrypt_app_tree
    _encrypt_app_tree(str(base / "runtime"), None, _RUNTIME_DLL, _APP)
    k_app = keylib.derive_k_app(master, _APP)
    (tmp_path / "patchwork").mkdir(exist_ok=True)
    return _patched_copy(tmp_path / "patchwork", k_app)  # 运行期形态 = K 内嵌


def _read_diag(base):
    return json.loads((base / "cache" / "diag.json").read_text(encoding="utf-8"))


def test_codekey_constants_mirror_keylib():
    """跨包常量对拍：运行期镜像单方漂移 = 全量 code_decrypt 失败，双端断言拦截。"""
    ck, _ = _codekey_mods()
    assert ck.BLOB_OVERHEAD == keylib.BLOB_OVERHEAD
    assert ck.INDEX_FILE_NAME == keylib.INDEX_FILE_NAME
    assert ck.INDEX_MODULE_ID == keylib.INDEX_MODULE_ID
    assert ck.INDEX_MAGIC == keylib.INDEX_MAGIC
    assert ck.NEUTRAL == "应用组件缺失或不完整，请重新安装或更新应用"   # §7.3 Q3 定稿文案


def test_codekey_finder_serves_app_imports(shell_env, tmp_path, monkeypatch,
                                           finder_clean):
    """§7.1 全链：install 三 stage 全过 → meta_path finder 独占供给 app.* 导入
    （marshal-exec、包语义、子包相对导入链、blob 起源）。"""
    ck, _env = _codekey_mods()
    master = hashlib.sha256(b"shell-key").digest()
    k_app = keylib.derive_k_app(master, _APP)
    kid = keylib.key_id_hex(k_app)
    patched = _encrypted_deploy(shell_env, tmp_path, monkeypatch, master)
    _write_manifest(shell_env, kid)
    monkeypatch.setattr(ck, "_dll_path", lambda cfg: patched)   # exe 旁路径 → 测试补丁件

    ck.install(_env.load_env(refresh=True), kid)         # 缺失/不配对即在此中止
    mod = importlib.import_module("app.main")
    assert mod.VALUE == 42                               # main → from .sub import x 链
    assert importlib.import_module("app").APP == 1
    assert importlib.import_module("app.sub.x").N == 42
    app_mod = sys.modules["app"]
    assert isinstance(app_mod.__path__, list)            # 包语义（子包导入前提）
    assert app_mod.__spec__.origin.endswith(".enc")      # 供给来源 = blob（非 PathFinder）


def test_codekey_non_member_falls_through(shell_env, tmp_path, monkeypatch,
                                          finder_clean):
    """成员资格判定（§7.1）：不在册 app.* 回退 PathFinder → ModuleNotFoundError。"""
    ck, _env = _codekey_mods()
    master = hashlib.sha256(b"shell-key").digest()
    patched = _encrypted_deploy(shell_env, tmp_path, monkeypatch, master)
    _write_manifest(shell_env, keylib.key_id_hex(keylib.derive_k_app(master, _APP)))
    monkeypatch.setattr(ck, "_dll_path", lambda cfg: patched)
    ck.install(_env.load_env(refresh=True), keylib.key_id_hex(keylib.derive_k_app(master, _APP)))
    with pytest.raises(ImportError):
        importlib.import_module("app.nope")


def test_codekey_keylib_load_missing(shell_env, tmp_path, monkeypatch, finder_clean):
    """§7.3 stage=keylib_load：件缺失 → 中性文案进 error（壳错误页），细节进 detail。"""
    ck, _env = _codekey_mods()
    kid = keylib.key_id_hex(hashlib.sha256(b"k").digest())
    _write_manifest(shell_env, kid)
    monkeypatch.setattr(ck, "_dll_path", lambda cfg: str(tmp_path / "absent.dll"))
    with pytest.raises(ck.CodeProtectError):
        ck.install(_env.load_env(refresh=True), kid)
    d = _read_diag(shell_env)
    assert d["stage"] == "keylib_load"
    assert d["error"] == ck.NEUTRAL                      # Q3：错误页唯一文案
    assert "absent.dll" in d["detail"]                   # 开发者细节在 detail
    assert d["recoverable"] is False


def test_codekey_key_pair_check_mismatch(shell_env, tmp_path, monkeypatch,
                                         finder_clean):
    """§7.3 stage=key_pair_check：件与 manifest K 不配对（新旧混装）→ 中性文案。"""
    ck, _env = _codekey_mods()
    ka, kb = hashlib.sha256(b"A").digest(), hashlib.sha256(b"B").digest()
    patched = _patched_copy(tmp_path, kb)                # 件是 B 钥
    _write_manifest(shell_env, keylib.key_id_hex(ka))    # manifest 声称 A 钥
    monkeypatch.setattr(ck, "_dll_path", lambda cfg: patched)
    with pytest.raises(ck.CodeProtectError) as ei:
        ck.install(_env.load_env(refresh=True), keylib.key_id_hex(ka))
    assert ei.value.pkapp_diag_written is True           # bootstrap 兜底 diag 见此标记跳过
    d = _read_diag(shell_env)
    assert d["stage"] == "key_pair_check"
    assert d["error"] == ck.NEUTRAL


def test_codekey_decrypt_corrupt_blob(shell_env, tmp_path, monkeypatch,
                                      finder_clean):
    """§7.3 stage=code_decrypt：blob 损坏 → import 期写中性 diag（GCM 认证失败）。"""
    ck, _env = _codekey_mods()
    master = hashlib.sha256(b"shell-key").digest()
    k_app = keylib.derive_k_app(master, _APP)
    patched = _encrypted_deploy(shell_env, tmp_path, monkeypatch, master)
    _write_manifest(shell_env, keylib.key_id_hex(k_app))
    monkeypatch.setattr(ck, "_dll_path", lambda cfg: patched)
    cfg = _env.load_env(refresh=True)
    ck.install(cfg, keylib.key_id_hex(k_app))
    bp = shell_env / "runtime" / "app" / keylib.blob_name("app.main")
    data = bytearray(bp.read_bytes())
    data[40] ^= 0x01                                     # 密文任一字节翻转
    bp.write_bytes(bytes(data))
    with pytest.raises(ck.CodeProtectError):
        importlib.import_module("app.main")              # "app" 正常、app.main 解密失败
    d = _read_diag(shell_env)
    assert d["stage"] == "code_decrypt"
    assert d["error"] == ck.NEUTRAL
    assert "app.main" in d["detail"]                     # 定位到模块（AAD 绑定语义）


def test_codekey_index_missing_is_code_decrypt(shell_env, tmp_path, monkeypatch,
                                               finder_clean):
    """清单缺失（安装包被裁剪）→ install 阶段即 code_decrypt，中性文案。"""
    ck, _env = _codekey_mods()
    master = hashlib.sha256(b"shell-key").digest()
    k_app = keylib.derive_k_app(master, _APP)
    _encrypted_deploy(shell_env, tmp_path, monkeypatch, master)
    (shell_env / "runtime" / "app" / "index.enc").unlink()
    _write_manifest(shell_env, keylib.key_id_hex(k_app))
    monkeypatch.setattr(ck, "_dll_path",
                        lambda cfg: str(shell_env / "patched.dll"))
    keylib.patch_dll(_DLL, str(shell_env / "patched.dll"), k_app)
    with pytest.raises(ck.CodeProtectError):
        ck.install(_env.load_env(refresh=True), keylib.key_id_hex(k_app))
    d = _read_diag(shell_env)
    assert d["stage"] == "code_decrypt"
    assert d["error"] == ck.NEUTRAL


# ---------------------------------------------------------------- ★期1 S5★
# pk_x4 引导装载契约（keylib 停在 marshal.loads 之前；壳侧消费方见 shell.cpp
# boot_load_codekey）——ctypes 直调补丁件，无解释器依赖，锁定双端协议。


def _px4(patched: str):
    """pk_x4 ctypes 绑定：返回 (dll, call(runtime_root, buf_or_None, cap) -> (rc, need, out))。"""
    dll = ctypes.CDLL(patched)
    dll.pk_x4.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_ubyte),
                          ctypes.c_ulonglong,
                          ctypes.POINTER(ctypes.c_ulonglong)]
    dll.pk_x4.restype = ctypes.c_int

    def call(root: str, cap: int | None):
        need = ctypes.c_ulonglong(0)
        buf = (ctypes.c_ubyte * cap)() if cap else None
        rc = dll.pk_x4(root.encode("utf-8"), buf, cap or 0, ctypes.byref(need))
        out = bytes(bytearray(buf))[:need.value] if (buf and rc == 0) else None
        return rc, need.value, out

    return dll, call


def test_pk_x4_boot_contract(tmp_path):
    """pk_x4 两段式装载 ≡ pk_x1 原载荷（同补丁件 K 内嵌同源）+ 三负例路径 +
    blob 名公式 Python↔C 对拍（key.c sha256(mid) 定位漂移在此拦截）。"""
    key = hashlib.sha256(b"boot-key").digest()
    patched = _patched_copy(tmp_path, key)
    kl = KeyLib(patched)
    mid = keylib.APPLOCAL_BOOT_MID
    payload = marshal.dumps(compile("X = 1\n", "applocal/_codekey.py", "exec"))
    blob = kl.encrypt(key, mid, payload)

    # blob 名公式：C 侧定位（k_m1‖k_m2 还原 mid → sha256 hex + .enc）与 Python
    # 单源常量逐位一致——"applocal._codekey" 任一端漂移 = NOBLOB 全链失败
    assert keylib.blob_name(mid) == hashlib.sha256(
        mid.encode("utf-8")).hexdigest() + ".enc"

    root = tmp_path / "runtime"
    (root / "site-packages" / "applocal").mkdir(parents=True)
    (root / "site-packages" / "applocal" / keylib.blob_name(mid)).write_bytes(blob)
    _, call = _px4(patched)

    rc, need, _ = call(str(root), 0)                    # 两段式第一遍：探大小
    # need = 解密后载荷大小（blob − BLOB_OVERHEAD）——pk_x4 输出裸 marshal 载荷
    assert rc == -2 and need == len(payload) == len(blob) - keylib.BLOB_OVERHEAD
    rc, need, out = call(str(root), need)               # 第二遍：装载
    assert rc == 0 and out == payload                   # 裸 marshal 载荷（剥头后）

    rc, _, _ = call(str(tmp_path / "absent"), 0)        # NOBLOB：明文包常态
    assert rc == -7
    rc, need, _ = call(str(root), need - 1)             # cap 不足 → -2 回填载荷大小
    assert rc == -2 and need == len(payload)
    bp = root / "site-packages" / "applocal" / keylib.blob_name(mid)
    data = bytearray(bp.read_bytes())
    data[-1] ^= 0xFF                                    # GCM tag 翻转（过 FORMAT 达 AUTH）
    bp.write_bytes(bytes(data))
    rc, _, _ = call(str(root), need)                    # AUTH：K 不配对/损坏
    assert rc == -4
    bp.write_bytes(blob)
    rc, _, out = call(str(root), need)                  # 修复后恢复装载
    assert rc == 0 and out == payload


def test_mid_not_in_dll_strings():
    """mid 明文/片段在 keylib 二进制 strings 面 0 命中（k_m1/k_m2 偏置分散纪律；
    S1 实测：static const 明文会被 MSVC 优化器折叠进 .rdata——此断言防回归）。
    "/site-packages/applocal/" 目录布局片段允许存在（包目录结构本可见，非 mid）。"""
    raw = open(_DLL, "rb").read()
    assert b"applocal._codekey" not in raw              # 完整 mid
    assert b"applocal." not in raw                      # k_m1 还原形（偏置前明文）
    assert b"_codekey" not in raw                       # k_m2 还原形


# ------------------------------------------------------- ★review 后补防线★


def test_dll_version_pair():
    """dll 名版本抽取：双平台命名 + basename 纪律（路径目录数字不污染）+ 异形态。"""
    assert assemble._dll_version_pair("python312.dll") == (3, 12)
    assert assemble._dll_version_pair("libpython3.12.so") == (3, 12)
    assert assemble._dll_version_pair(os.path.join("D:", "rt", "3.13",
                                                   "python312.dll")) == (3, 12)
    assert assemble._dll_version_pair("python.dll") == (0, 0)   # 无版本数字


def test_compile_one_pyc_fallback_version_guard(tmp_path):
    """防线 B：回退打包机解释器时，打包机版本必须与 python_dll 名一致
    （不符 fail-fast——此前是注释声明过的静默风险）。同版 dll 名正常编译。"""
    src = tmp_path / "m.py"
    src.write_text("X = 1\n", encoding="utf-8")
    bad = f"python{sys.version_info[0]}{sys.version_info[1] + 1}.dll"
    with pytest.raises(assemble.BuildError, match="版本不符"):
        assemble._compile_one_pyc(None, bad, str(src),
                                  str(tmp_path / "m.pyc"), "m.py")
    ok = f"python{sys.version_info[0]}{sys.version_info[1]}.dll"
    assemble._compile_one_pyc(None, ok, str(src),
                              str(tmp_path / "m.pyc"), "m.py")
    assert isinstance(marshal.loads((tmp_path / "m.pyc").read_bytes()[16:]),
                      types.CodeType)


def test_ensure_same_runtime_version():
    """防线 A：Windows 代编 Android pyc 的两端版本互等（比较粒度 minor——
    marshal 兼容粒度；patchlevel 差异放行）。"""
    assemble._ensure_same_runtime_version("3.12.14", "3.12.7")   # minor 同 → 放行
    with pytest.raises(assemble.BuildError, match="minor 版本一致"):
        assemble._ensure_same_runtime_version("3.12.14", "3.13.1")


# ------------------------------------------------- ★档位1 补充防线★（keybuild / 隔离对拍 / app_hash）

def _pyc_tag() -> str:
    """运行解释器同源 pyc tag（assemble windows 流 pyc_tag 派生式同构）。"""
    return f"cpython-{sys.version_info.major}{sys.version_info.minor}"


def test_compile_keylib_windows_burns_k(tmp_path):
    """现场定制编译（MSVC 在位时）：产物无锚点常量（§3.1 每包一破模型），
    key_id ≡ derive 镜像，K_app 内嵌 roundtrip（encrypt 走参数、decrypt 走内嵌）。
    ★这是档位1 主路径的实地验证——CI 镜像须装 VS2022 BuildTools C++ 工具集，
    否则本用例 skip = 现场编译零验证（fallback 单测不能替代烧 K 断言）。"""
    from pkapp.packager import keybuild

    if keybuild._find_vcvars64() is None:
        pytest.skip("MSVC 未就位——档位1 主路径（现场编译烧 K）本跑零验证，"
                    "CI/构建机需安装 VS2022 BuildTools C++ 工具集")
    k_app = hashlib.sha256(b"burn-k").digest()
    out = str(tmp_path / "pkapp_key.dll")
    keybuild.compile_keylib("windows", k_app, out)
    with open(out, "rb") as f:
        assert keylib.ANCHOR not in f.read()             # 专属件无锚点标记
    kl = KeyLib(out)
    assert kl.key_id() == keylib.key_id_hex(k_app)
    payload = b"marshal payload \x00\x01"
    blob = kl.encrypt(k_app, "app.main", payload)
    assert kl.decrypt("app.main", blob) == payload


def test_keybuild_vendored_path_aligned_with_locate_dll():
    """★review 修复回归★：keybuild wheel 分支与 locate_dll 的 _vendor 定位必须
    同指包根（keybuild here 已是目录只剥一层 dirname；错一层 = wheel 形态现场
    编译恒找不到 _vendor/keylib/src → 静默退化为锚点补丁）。"""
    from pkapp.packager import keybuild, keylib

    here = os.path.dirname(os.path.abspath(keybuild.__file__))       # .../pkapp/packager
    vendored = os.path.join(os.path.dirname(here), "_vendor", "keylib", "src")
    anchor = os.path.dirname(os.path.dirname(os.path.abspath(keylib.__file__)))
    assert os.path.dirname(vendored) == os.path.join(anchor, "_vendor", "keylib")


def test_keylib_source_dir_env_takes_priority(tmp_path, monkeypatch):
    """keylib_source_dir 定位序：PKAPP_KEYLIB_SRC 恒最优先（自管源码覆盖）。"""
    from pkapp.packager import keybuild

    env_dir = tmp_path / "src"
    env_dir.mkdir()
    (env_dir / "key.c").write_text("/* fake */", encoding="utf-8")
    monkeypatch.setenv("PKAPP_KEYLIB_SRC", str(env_dir))
    assert keybuild.keylib_source_dir() == str(env_dir)


def test_find_ndk_env_and_version_order(tmp_path, monkeypatch):
    """NDK 定位：ANDROID_NDK_HOME 恒直返；标准 SDK 位多版本取最新（版本号数值
    排序非字典序）；全缺失 → None（toolchain 探测异常注入 + LOCALAPPDATA 定向
    tmp，任何构建机布局下结果恒定）。"""
    from pkapp.packager import keybuild

    direct = tmp_path / "my-ndk"
    direct.mkdir()
    monkeypatch.setenv("ANDROID_NDK_HOME", str(direct))
    assert keybuild._find_ndk() == str(direct)                       # env 直返

    monkeypatch.delenv("ANDROID_NDK_HOME")
    la = tmp_path / "la"
    ndk_root = la / "Android" / "Sdk" / "ndk"
    for v in ("25.1.8937393", "26.1.10909125", "9.9.9"):
        (ndk_root / v).mkdir(parents=True)
    monkeypatch.setenv("LOCALAPPDATA", str(la))
    monkeypatch.setattr("pkapp.toolchain.android_paths",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("测试隔离")))
    assert keybuild._find_ndk() == str(ndk_root / "26.1.10909125")   # 数值序取最新

    import shutil as _sh
    _sh.rmtree(ndk_root)
    monkeypatch.delenv("LOCALAPPDATA")
    monkeypatch.delenv("ANDROID_NDK_HOME", raising=False)
    assert keybuild._find_ndk() is None                              # 全缺失


def test_produce_keylib_fallback_matches_compiled_key_id(tmp_path, monkeypatch):
    """退化路径语义等价（§3.3）：编译失手 → 预制件锚点补丁，产物 key_id 仍 ≡
    SHA256(K_app)[:16]——闸门语义零差异，两条路径 key_id 可互换比对。"""
    from pkapp.packager import keybuild

    def boom(*_a, **_k):
        raise KeyLibError("测试强制：编译不可得")

    monkeypatch.setattr(keybuild, "compile_keylib", boom)
    k_app = hashlib.sha256(b"fallback-k").digest()
    out = str(tmp_path / "pkapp_key.dll")
    assert keybuild.produce_keylib("windows", k_app, out) == "fallback"
    assert KeyLib(out).key_id() == keylib.key_id_hex(k_app)


def test_produce_keylib_double_failure(tmp_path, monkeypatch):
    """双失败负例：现场编译不可得 × 预制件缺失 → 明示报错（不静默、无空产物）。"""
    from pkapp.packager import keybuild

    def boom(*_a, **_k):
        raise KeyLibError("测试强制：编译不可得")

    monkeypatch.setattr(keybuild, "compile_keylib", boom)
    monkeypatch.setattr(keybuild, "locate_dll", lambda _p: None)
    with pytest.raises(KeyLibError, match="预制件缺失"):
        keybuild.produce_keylib("windows", b"\x01" * 32,
                                str(tmp_path / "pkapp_key.dll"))


def test_cross_app_isolation(tmp_path):
    """§1.1 横向隔离：同 master 异 app_id → 异 K；A 件解 B 包 blob 必败、B 件
    自开；件级 key_id 互异（跨包闸门在件形态下成立）。"""
    master = hashlib.sha256(b"shared-master").digest()
    ka = keylib.derive_k_app(master, "app-a")
    kb = keylib.derive_k_app(master, "app-b")
    assert ka != kb
    assert keylib.key_id_hex(ka) != keylib.key_id_hex(kb)
    da, db = tmp_path / "a", tmp_path / "b"
    da.mkdir()
    db.mkdir()
    pa, pb = _patched_copy(da, ka), _patched_copy(db, kb)
    blob_b = KeyLib(pb).encrypt(kb, "app.main", b"payload-b")
    assert KeyLib(pb).decrypt("app.main", blob_b) == b"payload-b"
    with pytest.raises(KeyLibError):
        KeyLib(pa).decrypt("app.main", blob_b)


def test_app_hash_plaintext_contract(tmp_path):
    """§3.2 app_hash 新语义契约（加密前明文摘要）：确定性（G5）+ 重编译稳定 +
    源码变化敏感 + 资源原文变化敏感 + 缺 pyc fail-fast。"""
    from pkapp.packager.assemble import _app_hash_plaintext

    app = tmp_path / "app"
    _make_stage_app(tmp_path)
    tag = _pyc_tag()
    h1 = _app_hash_plaintext(str(app), tag)
    assert len(h1) == 64
    assert _app_hash_plaintext(str(app), tag) == h1     # 同输入恒同哈希
    _compile_stage_app(str(app))                        # 同源重编 → 载荷同 → 哈希同
    assert _app_hash_plaintext(str(app), tag) == h1
    (app / "main.py").write_text("from .sub import x\nVALUE = x.N + 1\n",
                                 encoding="utf-8")      # 源码变化 → 重编 → 敏感
    _compile_stage_app(str(app))
    h2 = _app_hash_plaintext(str(app), tag)
    assert h2 != h1
    (app / "data.bin").write_bytes(b"\x00\x01CHANGED")  # 非 .py 资源原文进摘要
    assert _app_hash_plaintext(str(app), tag) != h2
    (app / "__pycache__" / f"__init__.{tag}.pyc").unlink()
    with pytest.raises(assemble.BuildError, match="app_hash 缺 pyc"):
        _app_hash_plaintext(str(app), tag)


def test_app_hash_plaintext_master_independent(tmp_path, monkeypatch):
    """app_hash 与 K_master 零耦合：无 master 环境照常工作且不触发 keygen
    （摘要在加密步骤之前算，派生链不参与——master 文件 0 落盘）。"""
    from pkapp.packager.assemble import _app_hash_plaintext

    monkeypatch.delenv("PKAPP_MASTER_KEY", raising=False)
    _make_stage_app(tmp_path)
    h = _app_hash_plaintext(str(tmp_path / "app"), _pyc_tag())
    assert len(h) == 64
    assert not (tmp_path / "master.key").exists()       # 未触碰 master 解析
