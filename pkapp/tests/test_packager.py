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
              "python_dll", "entry", "runtime_hash", "app_hash", "ui_hash",
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


def test_managed_wheels_cache(project, wheels_dir, tmp_path, mock_runtime):
    """★v1.2★ wheel 缓存托管：缺省构建（不带 --wheels-dir）落到
    build/platform-windows/wheels 并离线命中；二跑 G1 字节级一致。"""
    import shutil

    cache = os.path.join(project, "build", "platform-windows", "wheels")
    shutil.copytree(wheels_dir, cache)                      # 预置热缓存（fixture 同源）
    out = str(tmp_path / "managed.spk")
    fields = _build(project, None, out)
    assert fields["applocal_version"] == "0.1.0"
    out2 = str(tmp_path / "managed2.spk")
    _build(project, None, out2)
    assert open(out, "rb").read() == open(out2, "rb").read()


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
    # 布局：manifest + site-packages + app + ui；无解释器件（_pth/DLLs/python zip 不存在）
    names = {p for p, _ in spk.read_spk(out)}
    assert spk.MANIFEST_ENTRY in names
    assert "app/main.py" in names
    assert "ui/index.html" in names
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


def test_zip_lib_pure_pyc(tmp_path):
    """_zip_lib（★v0.7★ zip 内恒纯 pyc）：有 pyc 的 .py 不进 zip（扁平 .pyc）；
    无 pyc 的 .py 兜底写入；无 pyc_tag 时不查 pyc，全部按 .py 写入。"""
    lib = tmp_path / "lib"
    (lib / "pkg" / "__pycache__").mkdir(parents=True)
    (lib / "pkg" / "__init__.py").write_text("X = 1\n", encoding="utf-8")
    (lib / "pkg" / "__pycache__" / "__init__.cpython-312.pyc").write_bytes(b"fake")
    (lib / "lone.py").write_text("Y = 2\n", encoding="utf-8")   # 无 pyc → 兜底
    out = str(tmp_path / "lib.zip")
    assemble._zip_lib(str(lib), out, pyc_tag="cpython-312")
    assert set(zipfile.ZipFile(out).namelist()) == {"pkg/__init__.pyc", "lone.py"}
    out2 = str(tmp_path / "lib2.zip")
    assemble._zip_lib(str(lib), out2)
    assert set(zipfile.ZipFile(out2).namelist()) == {"pkg/__init__.py", "lone.py"}


def test_default_layout_py_sources(project, wheels_dir, tmp_path):
    """★v0.7★ 默认布局：site-packages 恒只带 .py（无 pyc/__pycache__——目录树
    首启自动建缓存，源码内省/RECORD 零副作用）；app/ 恒保留源码；golden B.z 仍过。
    （stdlib zip 纯 pyc 断言在 test_zip_lib_pure_pyc——mock 快照 python.exe 为占位、
    回退打包机 3.10 编译，集成里 pyc tag 与 cpython-312 不匹配走兜底写 .py。）"""
    out = str(tmp_path / "v7.spk")
    fields = _build(project, wheels_dir, out)
    assert fields["format_version"] == "1"
    with zipfile.ZipFile(out) as zf:
        stage = str(tmp_path / "stage")
        zf.extractall(stage)
    sp = os.path.join(stage, "site-packages")
    assert os.path.isfile(os.path.join(sp, "applocal", "__init__.py"))
    assert os.path.isfile(os.path.join(sp, "certifi", "cacert.pem"))  # 数据文件不动
    sp_files = [os.path.join(dp, f) for dp, _dn, fs in os.walk(sp) for f in fs]
    assert sp_files
    assert not any(f.endswith(".pyc") for f in sp_files)
    assert not any("__pycache__" in f for f in sp_files)
    assert os.path.isfile(os.path.join(stage, "app", "main.py"))      # app 源码恒保留
    golden_mod.assert_bz(stage, "python312.dll")
