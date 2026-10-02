"""packager 全管线 + golden 断言（G1–G5、G7；G8/G11 属 M2/真快照项）。"""
import os
import zipfile

import pytest

from pkapp.appspec import SpecError, load
from pkapp.commands.create import cmd_create
from pkapp.packager import assemble
from pkapp.packager import golden as golden_mod
from pkapp.packager import manifest as mf
from pkapp.packager import sign, spk
from pkapp.packager.runtime import dll_stem


def _build(project, wheels_dir, out, **kw):
    spec = load(os.path.join(project, "pkapp.toml"))
    return assemble.build_spk(project, spec, "windows", out,
                              private_key=os.path.join(project, ".pkapp", "sign.key"),
                              wheels_dir=wheels_dir, **kw)


def test_build_and_golden(project, wheels_dir, tmp_path):
    out = str(tmp_path / "demo.spk")
    fields = _build(project, wheels_dir, out)
    # G2 manifest 键位齐全
    for k in ("format_version", "app_version", "min_app_version", "applocal_version",
              "python_dll", "entry", "runtime_hash", "app_hash", "dist_hash",
              "spk_hash", "signature"):
        assert fields.get(k), f"G2: {k} 非空失败"
    assert fields["entry"] == "app.main:app"
    assert fields["python_dll"] == "python312.dll"
    assert fields["applocal_version"] == "0.1.0"
    # 验签链（G4 正向）
    pub = sign.public_key_hex(os.path.join(project, ".pkapp", "sign.key"))
    got, _ = mf.verify_spk(out, pub)
    assert got["app_version"] == "0.1.0"
    # B.z①–⑥（对解包 stage）
    with zipfile.ZipFile(out) as zf:
        stage = str(tmp_path / "stage")
        zf.extractall(stage)
    golden_mod.assert_bz(stage, "python312.dll")


def test_reproducible(project, wheels_dir, tmp_path):   # G1
    outs = []
    for i in (1, 2):
        p = str(tmp_path / f"r{i}.spk")
        _build(project, wheels_dir, p)
        outs.append(open(p, "rb").read())
    assert outs[0] == outs[1], "G1: 同输入两次构建必须字节级一致"


def test_tamper_detected(project, wheels_dir, tmp_path):  # G4 负向
    out = str(tmp_path / "t.spk")
    _build(project, wheels_dir, out)
    entries = spk.read_spk(out)
    # 改写 app 内容但不改 manifest → spk_hash 必须不一致
    tampered = [(p, b"tampered" if p.startswith("app/") else c) for p, c in entries]
    out2 = str(tmp_path / "t2.spk")
    spk.write_spk(out2, tampered)
    pub = sign.public_key_hex(os.path.join(project, ".pkapp", "sign.key"))
    with pytest.raises(ValueError, match="spk_hash"):
        mf.verify_spk(out2, pub)
    # 改写 manifest 正文 → 验签失败（签名覆盖正文）
    tampered2 = [(p, c.replace(b"app_version = 0.1.0", b"app_version = 9.9.9")
                  if p == spk.MANIFEST_ENTRY else c) for p, c in entries]
    out3 = str(tmp_path / "t3.spk")
    spk.write_spk(out3, tampered2)
    with pytest.raises(ValueError, match="验签失败"):
        mf.verify_spk(out3, pub)


def test_closure_negative(project, wheels_dir, tmp_path, mock_runtime):   # G7 负向
    # 摘掉 libcrypto → _ssl.pyd 闭包不完整 → 构建失败
    os.remove(os.path.join(mock_runtime, "DLLs", "libcrypto-3-x64.dll"))
    with pytest.raises(assemble.BuildError, match="闭包不完整"):
        _build(project, wheels_dir, str(tmp_path / "x.spk"))


def _build_android(project, wheels_dir, out, **kw):
    spec = load(os.path.join(project, "pkapp.toml"))
    return assemble.build_spk(project, spec, "android", out,
                              private_key=os.path.join(project, ".pkapp", "sign.key"),
                              wheels_dir=wheels_dir, **kw)


def test_android_build(project, mock_android_runtime, wheels_dir, tmp_path):    # M2 android 管线
    from hashlib import sha256 as _sha

    abi = "arm64-v8a"
    out = str(tmp_path / "demo-android.spk")
    fields = _build_android(project, wheels_dir, out)

    assert fields["python_dll"] == "libpython3.12.so"
    assert fields["applocal_version"] == "0.1.0"
    bundle = os.path.join(mock_android_runtime, abi, "libpythonbundle.so")
    bundle_hash = _sha(open(bundle, "rb").read()).hexdigest()
    assert fields["runtime_hash"] == f"sha256:{bundle_hash}"
    # 验签链（G4 正向）
    pub = sign.public_key_hex(os.path.join(project, ".pkapp", "sign.key"))
    got, _ = mf.verify_spk(out, pub)
    assert got["python_dll"] == "libpython3.12.so"
    # 布局：manifest + site-packages + app + dist；无解释器件（_pth/DLLs/python zip 不存在）
    names = {p for p, _ in spk.read_spk(out)}
    assert spk.MANIFEST_ENTRY in names
    assert "app/main.py" in names
    assert "dist/index.html" in names
    assert "site-packages/applocal/__init__.py" in names
    assert not any(n.endswith("._pth") or n.startswith("DLLs/") for n in names)
    # G1 android：可复现
    out2 = str(tmp_path / "demo-android-2.spk")
    _build_android(project, wheels_dir, out2)
    assert open(out, "rb").read() == open(out2, "rb").read()


def test_android_runtime_resolve_negative(project, tmp_path):
    """fail fast：缺 bundle / 缺 abi 目录（托管快照路径，managed_runtime_dir 同源）。"""
    from pkapp.packager.runtime import RuntimeResolveError, resolve
    from pkapp.tools.mockkit import make_mock_android_runtime

    spec = load(os.path.join(project, "pkapp.toml"))
    bad = str(tmp_path / "bad-rt")
    make_mock_android_runtime(bad, abis=("arm64-v8a",))
    os.remove(os.path.join(bad, "arm64-v8a", "libpythonbundle.so"))
    # 逃生门路径只断言布局（version 取 spec 声明），不依赖托管缓存
    from dataclasses import replace
    spec_bad = replace(spec, android_runtime_dir=bad)
    with pytest.raises(RuntimeResolveError, match="libpythonbundle"):
        resolve(spec_bad, "android")
    make_mock_android_runtime(bad, abis=("arm64-v8a",))
    with pytest.raises(RuntimeResolveError, match="子目录"):
        resolve(spec_bad, "android", abis=("x86_64",))


def test_min_app_version_selfcheck(tmp_path):             # G5
    root = str(tmp_path / "demo5")
    assert cmd_create("demo5", root, no_venv=True) == 0
    toml = open(os.path.join(root, "pkapp.toml")).read() \
        .replace('min_app_version = "0.1.0"', 'min_app_version = "0.2.0"')
    with open(os.path.join(root, "pkapp.toml"), "w") as f:
        f.write(toml)
    with pytest.raises(SpecError, match="min_app_version"):
        load(os.path.join(root, "pkapp.toml"))


def test_install_dir_clean(tmp_path):                     # G6/G10
    d = str(tmp_path / "MyApp")
    os.makedirs(d)
    golden_mod.assert_install_dir_clean(d, "MyApp")       # 干净 → 过
    open(os.path.join(d, "MyApp._pth"), "w").close()
    with pytest.raises(AssertionError, match="fallback"):
        golden_mod.assert_install_dir_clean(d, "MyApp")
    os.remove(os.path.join(d, "MyApp._pth"))
    open(os.path.join(d, "evil.py"), "w").close()
    with pytest.raises(AssertionError, match="G10"):
        golden_mod.assert_install_dir_clean(d, "MyApp")


def test_dll_stem_derivation():                           # B.x 派生（V13）
    assert dll_stem("python312.dll") == "python312"
    assert dll_stem("python313.dll") == "python313"
