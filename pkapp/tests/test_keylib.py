"""keylib 契约测试（CODE_PROTECTION_DESIGN.md §5 / 阶段1 验收）。

参照实现 = cryptography（OpenSSL）AESGCM + 标准库 hmac：pkapp_encrypt 产物与
Python 侧按同规格重组的 blob 必须逐字节一致——等价于对 C 内 GCM/HMAC 全链做
已知向量验证（nonce = HMAC-SHA256(K, module_id)[:12]、AAD = module_id、
tag = GCM 认证标签）。解密/补丁链路用补丁后的 dll 副本驱动（package 闸门同款）。
"""
from __future__ import annotations

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

from pkapp.packager import keylib
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


def test_ensure_code_key(tmp_path):
    key, generated = keylib.ensure_code_key(str(tmp_path))
    assert generated and len(key) == 32
    key2, generated2 = keylib.ensure_code_key(str(tmp_path))
    assert not generated2 and key2 == key          # 幂等：已有 K 不重生成
    assert (tmp_path / ".pkapp" / "code.key").is_file()
    gi = tmp_path / ".gitignore"
    assert gi.is_file() and ".pkapp/" in gi.read_text(encoding="utf-8")


def test_ensure_code_key_gitignore_no_duplicate(tmp_path):
    (tmp_path / ".gitignore").write_text("build/\n.pkapp/\n", encoding="utf-8")
    keylib.ensure_code_key(str(tmp_path))
    assert (tmp_path / ".gitignore").read_text(encoding="utf-8") == "build/\n.pkapp/\n"


def test_ensure_code_key_rejects_corrupt(tmp_path):
    kp = tmp_path / ".pkapp" / "code.key"
    kp.parent.mkdir(parents=True)
    kp.write_text("zz", encoding="ascii")
    with pytest.raises(KeyLibError):
        keylib.ensure_code_key(str(tmp_path))


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
    return app


def test_encrypt_app_tree_stage_contract(lib, tmp_path):
    """§6.1 全契约：keygen → blob 落盘 ≡ 参照实现 → 索引 → 删明文 → 资源保留。"""
    from pkapp.packager.assemble import _encrypt_app_tree

    project, app = tmp_path / "proj", tmp_path / "app"
    key_file = project / ".pkapp" / "code.key"
    _make_stage_app(tmp_path)
    # 预置固定 K（keygen 路径已由 test_ensure_code_key 覆盖）
    key = hashlib.sha256(b"stage-key").digest()
    key_file.parent.mkdir(parents=True)
    key_file.write_text(key.hex(), encoding="ascii")

    kid = _encrypt_app_tree(str(app), _RUNTIME_DLL, str(project))
    assert kid == keylib.key_id_hex(key)               # manifest code_key_id 配对值

    # 逐 blob：补丁件（K 内嵌 = 运行期形态）解密 → marshal 载荷合法 + co_filename 归一
    (tmp_path / "patchwork").mkdir()
    patched = KeyLib(_patched_copy(tmp_path / "patchwork", key))
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
    # K 文件未被触碰（读取路径不重生成）
    assert key_file.read_text(encoding="ascii") == key.hex()


def _walk_all(root):
    out = []
    for dp, _dn, fns in os.walk(root):
        for fn in fns:
            out.append(os.path.join(dp, fn))
    return out


def test_encrypt_app_tree_missing_dll(tmp_path, monkeypatch):
    """构建期判定（§8）：key-holder 件缺失 → 构建报错，不做静默降级。"""
    from pkapp.packager import assemble

    _make_stage_app(tmp_path)
    monkeypatch.setattr(assemble, "locate_dll", lambda p: None)
    (tmp_path / ".pkapp").mkdir()
    with pytest.raises(assemble.BuildError, match="key-holder"):
        assemble._encrypt_app_tree(str(tmp_path / "app"), _RUNTIME_DLL,
                                   str(tmp_path))


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


# ---------------------------------------------------------------- 阶段2b：package 补丁与闸门
def _proj_with_key(tmp_path, key: bytes):
    proj = tmp_path / "proj"
    (proj / ".pkapp").mkdir(parents=True)
    (proj / ".pkapp" / "code.key").write_text(key.hex(), encoding="ascii")
    return str(proj)


def test_stage_keylib_patches_and_gates(tmp_path, monkeypatch):
    """§6.2 正向：通用件 staging 副本补 K 包裹态 → 件 key_id ≡ manifest 配对值；
    补丁件按运行期形态打开 K 加密的 blob。"""
    from pkapp.commands.package import _stage_keylib

    monkeypatch.delenv("PKAPP_KEYLIB", raising=False)
    key = hashlib.sha256(b"pkg-key").digest()
    proj = _proj_with_key(tmp_path / "p1", key)
    stage = str(tmp_path / "p1" / "stage")
    os.makedirs(stage)
    assert _stage_keylib(proj, stage, keylib.key_id_hex(key)) == 0
    out = os.path.join(stage, "pkapp_key.dll")
    assert os.path.isfile(out)
    kl = KeyLib(out)
    assert kl.key_id() == keylib.key_id_hex(key)
    blob = kl.encrypt(key, "app.main", b"payload")       # encrypt 恒走参数 K
    assert kl.decrypt("app.main", blob) == b"payload"    # decrypt 走内嵌 K（运行期同构）
    # 分发原件零触碰（补丁只在 staging 副本上）
    assert open(out, "rb").read() != open(_DLL, "rb").read()


def test_stage_keylib_rejects_mismatched_key(tmp_path, monkeypatch):
    """跨 key 闸门：code.key 与 manifest code_key_id 不配对（K 丢失重生成/新旧
    混装）→ package 拒绝（返回 2）。"""
    from pkapp.commands.package import _stage_keylib

    monkeypatch.delenv("PKAPP_KEYLIB", raising=False)
    ka, kb = hashlib.sha256(b"A").digest(), hashlib.sha256(b"B").digest()
    proj = _proj_with_key(tmp_path / "p2", ka)
    stage = str(tmp_path / "p2" / "stage")
    os.makedirs(stage)
    assert _stage_keylib(proj, stage, keylib.key_id_hex(kb)) == 2
    # 失败保留 staging 现场（同壳公钥闸门语义）：补丁件在场供排查，但不出货
    assert os.path.isfile(os.path.join(stage, "pkapp_key.dll"))


def test_stage_keylib_missing_key(tmp_path, monkeypatch):
    """spk 已加密而 code.key 缺失 = 不可交付：报错且不 keygen（新 K 必不配对，
    静默生成只会掩盖密钥丢失）。"""
    from pkapp.commands.package import _stage_keylib

    monkeypatch.delenv("PKAPP_KEYLIB", raising=False)
    proj = str(tmp_path / "p3")
    os.makedirs(proj)
    stage = str(tmp_path / "p3" / "stage")
    os.makedirs(stage)
    assert _stage_keylib(proj, stage, "0" * 32) == 2
    assert not os.path.isfile(os.path.join(proj, ".pkapp", "code.key"))


def test_stage_keylib_mode_b_no_patch(tmp_path, monkeypatch):
    """模式 B（PKAPP_KEYLIB 自管件，K 编译期内嵌）：不补丁仅落位，闸门仍生效。"""
    from pkapp.commands.package import _stage_keylib

    key = hashlib.sha256(b"mode-b").digest()
    own = tmp_path / "own" / "pkapp_key.dll"
    own.parent.mkdir(parents=True)
    keylib.patch_dll(_DLL, str(own), key)
    before = own.read_bytes()
    monkeypatch.setenv("PKAPP_KEYLIB", str(own))
    proj = _proj_with_key(tmp_path / "p4", key)          # 模式 B 不读项目 K
    stage = str(tmp_path / "p4" / "stage")
    os.makedirs(stage)
    assert _stage_keylib(proj, stage, keylib.key_id_hex(key)) == 0
    assert (tmp_path / "p4" / "stage" / "pkapp_key.dll").read_bytes() == before  # 逐字节未改写
    # 自管件 key_id 与 manifest 不符同样被闸门拦下
    stage2 = str(tmp_path / "p4" / "stage2")
    os.makedirs(stage2)
    assert _stage_keylib(proj, stage2, keylib.key_id_hex(hashlib.sha256(b"X").digest())) == 2


# ---------------------------------------------------------------- 阶段2b-android：异平台件落位
def test_stage_keylib_android_patches_and_gates(tmp_path, monkeypatch,
                                                android_keylib_so):
    """android .so（构建机无法 dlopen ELF）：补丁仍走锚点字节改写，key_id 闸门
    改用 Python 镜像 key_id_hex(K) 比对（ctypes 实测仅 windows 平台件可用）。"""
    from pkapp.commands.package import _stage_keylib

    monkeypatch.delenv("PKAPP_KEYLIB", raising=False)    # 补丁路径必须走文件落位
    key = hashlib.sha256(b"and-key").digest()
    proj = _proj_with_key(tmp_path / "pa", key)
    stage = str(tmp_path / "pa" / "stage")
    os.makedirs(stage)
    assert _stage_keylib(proj, stage, keylib.key_id_hex(key), "android") == 0
    out = os.path.join(stage, "lib_pkapp_key.so")
    assert os.path.isfile(out)
    with open(out, "rb") as f:
        data = f.read()
    with open(android_keylib_so, "rb") as f:
        src = f.read()
    i = src.index(keylib.ANCHOR)
    assert keylib.ANCHOR not in data                     # 锚点已改写（不再含原值）
    assert data[i:i + 32] == bytes(k ^ m for k, m in zip(key, keylib._MASK))
    assert data[:i] == src[:i] and data[i + 32:] == src[i + 32:]   # 其余字节零扰动


def test_stage_keylib_android_rejects_mismatched_key(tmp_path, monkeypatch,
                                                     android_keylib_so):
    """android 闸门负向：code.key 与 manifest code_key_id 不配对 → rc=2
    （补丁件保留 staging 现场供排查，同 windows 语义）。"""
    from pkapp.commands.package import _stage_keylib

    monkeypatch.delenv("PKAPP_KEYLIB", raising=False)
    ka, kb = hashlib.sha256(b"A-and").digest(), hashlib.sha256(b"B-and").digest()
    proj = _proj_with_key(tmp_path / "pb", ka)
    stage = str(tmp_path / "pb" / "stage")
    os.makedirs(stage)
    assert _stage_keylib(proj, stage, keylib.key_id_hex(kb), "android") == 2
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


def _encrypted_deploy(base, tmp_path, key: bytes) -> str:
    """把 stage app 加密成运行态部署（blob + index.enc + 明文资源），返回补丁件路径。"""
    _make_stage_app(base / "runtime")                    # app/ 树 → <runtime>/app
    project = tmp_path / "proj"
    (project / ".pkapp").mkdir(parents=True)
    (project / ".pkapp" / "code.key").write_text(key.hex(), encoding="ascii")
    from pkapp.packager.assemble import _encrypt_app_tree
    _encrypt_app_tree(str(base / "runtime" / "app"), _RUNTIME_DLL, str(project))
    (tmp_path / "patchwork").mkdir(exist_ok=True)
    return _patched_copy(tmp_path / "patchwork", key)    # 运行期形态 = K 内嵌


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
    key = hashlib.sha256(b"shell-key").digest()
    kid = keylib.key_id_hex(key)
    patched = _encrypted_deploy(shell_env, tmp_path, key)
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
    key = hashlib.sha256(b"shell-key").digest()
    patched = _encrypted_deploy(shell_env, tmp_path, key)
    _write_manifest(shell_env, keylib.key_id_hex(key))
    monkeypatch.setattr(ck, "_dll_path", lambda cfg: patched)
    ck.install(_env.load_env(refresh=True), keylib.key_id_hex(key))
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
    key = hashlib.sha256(b"shell-key").digest()
    patched = _encrypted_deploy(shell_env, tmp_path, key)
    _write_manifest(shell_env, keylib.key_id_hex(key))
    monkeypatch.setattr(ck, "_dll_path", lambda cfg: patched)
    cfg = _env.load_env(refresh=True)
    ck.install(cfg, keylib.key_id_hex(key))
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
    key = hashlib.sha256(b"shell-key").digest()
    _encrypted_deploy(shell_env, tmp_path, key)
    (shell_env / "runtime" / "app" / "index.enc").unlink()
    _write_manifest(shell_env, keylib.key_id_hex(key))
    monkeypatch.setattr(ck, "_dll_path",
                        lambda cfg: str(shell_env / "patched.dll"))
    keylib.patch_dll(_DLL, str(shell_env / "patched.dll"), key)
    with pytest.raises(ck.CodeProtectError):
        ck.install(_env.load_env(refresh=True), keylib.key_id_hex(key))
    d = _read_diag(shell_env)
    assert d["stage"] == "code_decrypt"
    assert d["error"] == ck.NEUTRAL
