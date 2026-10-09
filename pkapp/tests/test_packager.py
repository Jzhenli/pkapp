"""packager 全管线 + golden 断言（G1–G5、G7；G8/G11 属 M2/真快照项）。"""
import hashlib
import os
import types
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
    """★v1.4★ wheel 托管缓存全局化：缺省构建（不带 --wheels-dir）落到
    <PKAPP_CACHE>/wheels/<platform> 并离线命中；二跑 G1 字节级一致。"""
    import shutil

    cache = assemble._wheels_cache("windows")
    assert cache.startswith(os.environ["PKAPP_CACHE"])   # 全局托管根内，不入项目 build/
    os.makedirs(cache)
    for fn in os.listdir(wheels_dir):                    # 预置热缓存（fixture 同源）
        shutil.copy2(os.path.join(wheels_dir, fn), cache)
    out = str(tmp_path / "managed.spk")
    fields = _build(project, None, out)
    assert fields["applocal_version"] == "0.1.0"
    out2 = str(tmp_path / "managed2.spk")
    _build(project, None, out2)
    assert open(out, "rb").read() == open(out2, "rb").read()


def test_uncached_deps_version_aware(tmp_path):
    """★v1.4★ 全局缓存跨项目共享 → 名字+精确版本匹配：同名旧版本不得误判已缓存。"""
    wd = str(tmp_path / "w")
    os.makedirs(wd)
    for fn in ("fastapi-0.110.0-py3-none-any.whl", "uvicorn-0.30.0-py3-none-any.whl"):
        open(os.path.join(wd, fn), "wb").close()
    uncached = assemble._uncached_deps
    # 精确 pin：版本不命中 → 补齐；版本命中 → 剔除
    assert uncached(["fastapi==0.115.0"], wd) == ["fastapi==0.115.0"]
    assert uncached(["fastapi==0.110.0"], wd) == []
    # extras 段 + 精确 pin：版本感知必须生效（不退化为按名字）
    assert uncached(["fastapi[std]==0.115.0"], wd) == ["fastapi[std]==0.115.0"]
    assert uncached(["fastapi[std]==0.110.0"], wd) == []
    # 范围 / 无 pin：按名字（文件名无法表达区间，退化语义）
    assert uncached(["fastapi>=0.110"], wd) == []
    assert uncached(["uvicorn"], wd) == []
    assert uncached(["applocal==0.1.0"], wd) == ["applocal==0.1.0"]
    # PEP 440 轻量等价：1.0 == 1.0.0 补零对齐；通配 .* 前缀
    assert uncached(["fastapi==0.110"], wd) == []
    assert uncached(["fastapi==0.110.*"], wd) == []
    assert uncached(["uvicorn==0.29.*"], wd) == ["uvicorn==0.29.*"]
    # 冷启动：缓存目录不存在不裸崩（先建目录，全部需求进补齐）
    absent = str(tmp_path / "absent")
    assert uncached(["applocal==0.1.0"], absent) == ["applocal==0.1.0"]
    assert os.path.isdir(absent)


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


def test_default_layout_p0_consolidated(project, wheels_dir, tmp_path):
    """★P0 §4.1★ 收拢布局：site-packages = deps.zip（内 pyc-only，无 .py 源）
    + 散件目录（applocal/certifi flat pyc，数据文件原样）；zip 与散件均无
    __pycache__；app/ 恒保留源码；golden B.z 仍过；format_version = 2
    （integrity 侧车契约）。（mock 快照 python.exe 为占位、回退打包机解释器编译。）"""
    out = str(tmp_path / "v7.spk")
    fields = _build(project, wheels_dir, out)
    assert fields["format_version"] == "2"
    with zipfile.ZipFile(out) as zf:
        stage = str(tmp_path / "stage")
        zf.extractall(stage)
    sp = os.path.join(stage, "site-packages")
    deps = zipfile.ZipFile(os.path.join(sp, "deps.zip"))
    names = deps.namelist()
    assert names
    assert not any(n.endswith(".py") for n in names)            # zip 内 pyc-only
    assert any(n.endswith(".pyc") for n in names)
    assert not any("__pycache__" in n for n in names)
    assert os.path.isfile(os.path.join(sp, "loose", "applocal", "__init__.pyc"))  # 散件 flat pyc
    assert os.path.isfile(os.path.join(sp, "loose", "certifi", "cacert.pem"))    # 数据文件原样
    sp_files = [os.path.join(dp, f) for dp, _dn, fs in os.walk(sp) for f in fs]
    assert not any(f.endswith(".py") for f in sp_files)          # site-packages 无 .py 源
    assert not any("__pycache__" in f for f in sp_files)
    assert os.path.isfile(os.path.join(stage, "app", "main.py"))  # app 源码恒保留
    golden_mod.assert_bz(stage, "python312.dll")


def test_namespace_pkg_goes_loose(project, wheels_dir, tmp_path):
    """★G12 实跑回归★ PEP 420 命名空间包（无 __init__.py 的多段 namespace，如
    opentelemetry）不能进 deps.zip——zipimport 无法从 zip 认领（需真实目录枚举）
    → 整目录散件化，导入语义由 loose 真实目录承担。"""
    from pkapp.tools.mockkit import make_wheel

    make_wheel(wheels_dir, "otelapi", "1.0.0", {
        "nsotel/trace/__init__.py": "SPAN = 1\n",   # nsotel 目录无 __init__.py
        "nsotel/trace/core.py": "def span():\n    return SPAN\n",
    })
    toml = os.path.join(project, "pkapp.toml")       # 依赖声明式供给：须声明才进闭包
    with open(toml, encoding="utf-8") as f:
        text = f.read()
    with open(toml, "w", encoding="utf-8") as f:
        f.write(text.replace('"uvicorn>=0.30"', '"uvicorn>=0.30",\n    "otelapi>=1.0.0"', 1))
    out = str(tmp_path / "ns.spk")
    _build(project, wheels_dir, out)
    with zipfile.ZipFile(out) as zf:
        stage = str(tmp_path / "stage")
        zf.extractall(stage)
    dep = zipfile.ZipFile(os.path.join(stage, "site-packages", "deps.zip"))
    assert not any(n.startswith("nsotel") for n in dep.namelist())
    assert os.path.isfile(os.path.join(
        stage, "site-packages", "loose", "nsotel", "trace", "__init__.pyc"))
    golden_mod.assert_bz(stage, "python312.dll")


# ---------------------------------------------------------------- 代码加密构建链（CODE_PROTECTION_DESIGN §6）
def _enable_code_encryption(project):
    toml = os.path.join(project, "pkapp.toml")
    with open(toml, encoding="utf-8") as f:
        text = f.read()
    assert "[app]" in text
    with open(toml, "w", encoding="utf-8") as f:
        f.write(text.replace("[app]\n", "[app]\ncode_encryption = true\n", 1))


def _set_master(monkeypatch) -> bytes:
    """★档位1★ 固定 K_master 注入 env（构建侧 resolve 首选源；测试与家目录
    零接触）——K 不再持久化，派生即用（app_id 与 project fixture 同源 "demo"）。"""
    master = hashlib.sha256(b"packager-master").digest()
    monkeypatch.setenv("PKAPP_MASTER_KEY", master.hex())
    return master


def _enable_per_build_salt(project):
    toml = os.path.join(project, "pkapp.toml")
    with open(toml, encoding="utf-8") as f:
        text = f.read()
    assert "[app]" in text
    with open(toml, "w", encoding="utf-8") as f:
        f.write(text.replace("[app]\n", "[app]\nper_build_salt = true\n", 1))


def test_build_per_build_salt(tmp_path, project, wheels_dir, monkeypatch):
    """★档位1 §3.2 R-2 per-build 档端到端★（build 期接缝）：salt 随机 → 两次构建
    code_salt/code_key_id 互异（K 变 → 密文变，spk 不一致）；app_hash 跨构建恒同
    （明文 marshal 解耦——指纹语义与 K 彻底分离的核心承诺）。package 期按 manifest
    code_salt 重派生的闸门接缝由 test_keylib salt_roundtrip/corrupt_salt 覆盖。"""
    _enable_code_encryption(project)
    _enable_per_build_salt(project)
    _set_master(monkeypatch)
    f1 = _build(project, wheels_dir, str(tmp_path / "p1.spk"))
    f2 = _build(project, wheels_dir, str(tmp_path / "p2.spk"))
    assert f1["code_salt"] and f2["code_salt"] \
        and f1["code_salt"] != f2["code_salt"]                 # salt 每构建刷新
    assert f1["code_key_id"] != f2["code_key_id"]              # K 随 salt 漂移
    assert f1["app_hash"] == f2["app_hash"]                    # 指纹与 K 解耦
    bytes.fromhex(f1["code_salt"])                             # 64 hex 可读回（package 期契约）


def test_build_code_encrypted(project, wheels_dir, tmp_path, monkeypatch):   # §6.1 + G5 加密态
    from pkapp.packager import keylib

    _enable_code_encryption(project)
    key = keylib.derive_k_app(_set_master(monkeypatch), "demo")
    out1, out2 = str(tmp_path / "e1.spk"), str(tmp_path / "e2.spk")
    fields = _build(project, wheels_dir, out1)
    assert fields["code_key_id"] == keylib.key_id_hex(key)     # manifest ↔ K 配对
    with zipfile.ZipFile(out1) as zf:
        names = zf.namelist()
    assert "app/index.enc" in names                            # 加密清单
    app_entries = [n for n in names if n.startswith("app/")]
    assert not any(n.endswith((".py", ".pyc")) or "__pycache__" in n
                   for n in app_entries)                       # 删明文闸：spk 内无源码
    assert any(n.startswith("app/") and n.endswith(".enc")
               and n != "app/index.enc" for n in names)        # 模块 blob 在
    # G5：加密构建两跑字节级一致（确定性 nonce + 稳定 pyc 载荷）
    _build(project, wheels_dir, out2)
    assert open(out1, "rb").read() == open(out2, "rb").read()
    # 验签链覆盖 code_key_id 扩展键
    pub = sign.public_key_hex(os.path.join(project, ".pkapp", "sign.key"))
    got, _ = mf.verify_spk(out1, pub)
    assert got["code_key_id"] == fields["code_key_id"]


def test_android_build_code_encrypted(project, mock_android_runtime, wheels_dir,
                                      tmp_path, monkeypatch):
    """★android 加密链★（§6.1，与 windows 同链）：加密构建 → spk 内 app/ 全 .enc
    + index.enc、manifest 带 code_key_id；密文可用构建机 windows keylib 补丁件
    解开（加密器恒用构建机件，密文与目标平台无关）。"""
    import marshal
    import types

    from pkapp.packager import keylib

    dll = keylib.locate_dll("windows")
    assert dll, "keylib/build/pkapp_key.dll 未编译（先跑 keylib/build.bat）"
    _enable_code_encryption(project)
    out = str(tmp_path / "enc-android.spk")
    key = keylib.derive_k_app(_set_master(monkeypatch), "demo")
    fields = _build_android(project, wheels_dir, out)
    kid = keylib.key_id_hex(key)
    assert fields["code_key_id"] == kid                    # manifest ↔ K 配对
    with zipfile.ZipFile(out) as zf:
        names = zf.namelist()
        stage = str(tmp_path / "stage")
        zf.extractall(stage)
    assert "app/index.enc" in names                        # 加密清单
    app_entries = [n for n in names if n.startswith("app/")]
    assert not any(n.endswith((".py", ".pyc")) or "__pycache__" in n
                   for n in app_entries)                   # 删明文闸：spk 内无源码
    assert any(n.startswith("app/") and n.endswith(".enc")
               and n != "app/index.enc" for n in names)    # 模块 blob 在
    assert "site-packages/applocal/__init__.py" in names   # 加密只覆盖 app/
    assert "ui/index.html" in names                        # ui 恒存在
    # 密文可解：windows 件补丁 K 内嵌（运行期形态）→ index + 模块 blob 全打开
    patched = str(tmp_path / "pkapp_key.patched.dll")
    keylib.patch_dll(dll, patched, key)
    kl = keylib.KeyLib(patched)
    with open(os.path.join(stage, "app", "index.enc"), "rb") as f:
        text = kl.decrypt(keylib.INDEX_MODULE_ID, f.read()).decode("utf-8")
    assert text.startswith(keylib.INDEX_MAGIC)
    assert "M app.main" in text
    with open(os.path.join(stage, "app", keylib.blob_name("app.main")), "rb") as f:
        main_blob = f.read()
    code = marshal.loads(kl.decrypt("app.main", main_blob))
    assert isinstance(code, types.CodeType)
    assert code.co_filename == "main.py"
    # 验签链覆盖 code_key_id 扩展键
    pub = sign.public_key_hex(os.path.join(project, ".pkapp", "sign.key"))
    got, _ = mf.verify_spk(out, pub)
    assert got["code_key_id"] == kid


# ---------------------------------------------------------------- 构建期混淆层（§13 S3/S4）
def _enable_code_obfuscation(project):
    toml = os.path.join(project, "pkapp.toml")
    with open(toml, encoding="utf-8") as f:
        text = f.read()
    assert "[app]" in text
    with open(toml, "w", encoding="utf-8") as f:
        f.write(text.replace("[app]\n", "[app]\ncode_obfuscation = true\n", 1))


def _collect_local_names(code):
    """递归收集 code 树全部局部名（varnames/cellvars/freevars；co_names 是全局/
    属性名——模板 main.py 的 .data_dir 属性访问也在其中，故不可混入）。"""
    out = set()
    stack = [code]
    while stack:
        c = stack.pop()
        out.update(c.co_varnames)
        out.update(c.co_cellvars)
        out.update(c.co_freevars)
        for k in c.co_consts:
            if isinstance(k, types.CodeType):
                stack.append(k)
    return out


def test_build_code_obfuscated(project, wheels_dir, tmp_path):   # §13 + G5 混淆态
    import marshal

    _enable_code_obfuscation(project)
    out1, out2 = str(tmp_path / "o1.spk"), str(tmp_path / "o2.spk")
    fields = _build(project, wheels_dir, out1)
    with zipfile.ZipFile(out1) as zf:
        names = zf.namelist()
        pycs = {n: zf.read(n) for n in names
                if n.startswith("app/") and n.endswith(".pyc")}
    assert pycs, "app/ 编译应产出 pyc"
    renamed_any = False
    for n, raw in pycs.items():
        code = marshal.loads(raw[16:])             # 剥 16 字节 pyc 头
        assert code.co_filename.endswith(".py")
        locals_ = _collect_local_names(code)
        assert "data_dir" not in locals_           # 模板 app() 的局部变量已改名
        renamed_any |= any(x.startswith("_o") for x in locals_)
    assert renamed_any, "pyc 内应出现 _o* 改名符号"
    # 磁盘源码恒不改写（app/ 恒保留源码 + importlib checked-hash 对磁盘源自洽）
    assert "app/main.py" in names
    with open(os.path.join(project, "app", "main.py"), encoding="utf-8") as f:
        assert "data_dir" in f.read()
    # G5：混淆构建双跑 pyc 字节级一致
    _build(project, wheels_dir, out2)
    with zipfile.ZipFile(out2) as zf2:
        for n, raw in pycs.items():
            assert zf2.read(n) == raw, f"G5: {n} 两跑不一致"


def test_build_code_obfuscated_and_encrypted(project, wheels_dir, tmp_path,
                                             monkeypatch):
    """★混淆+加密叠加★（§13）：blob 解出的 code 同样无原局部名且含 _o*。"""
    import marshal

    from pkapp.packager import keylib

    dll = keylib.locate_dll("windows")
    assert dll, "keylib/build/pkapp_key.dll 未编译（先跑 keylib/build.bat）"
    _enable_code_obfuscation(project)
    _enable_code_encryption(project)
    out = str(tmp_path / "oe.spk")
    key = keylib.derive_k_app(_set_master(monkeypatch), "demo")
    fields = _build(project, wheels_dir, out)
    assert fields["code_key_id"] == keylib.key_id_hex(key)
    with zipfile.ZipFile(out) as zf:
        names = zf.namelist()
        stage = str(tmp_path / "stage")
        zf.extractall(stage)
    # 删明文闸：混淆不改变加密链的删明文契约
    assert not any(n.endswith((".py", ".pyc")) or "__pycache__" in n
                   for n in names if n.startswith("app/"))
    assert "app/index.enc" in names
    patched = str(tmp_path / "pkapp_key.patched.dll")
    keylib.patch_dll(dll, patched, key)
    kl = keylib.KeyLib(patched)
    with open(os.path.join(stage, "app", keylib.blob_name("app.main")), "rb") as f:
        main_blob = f.read()
    code = marshal.loads(kl.decrypt("app.main", main_blob))
    assert isinstance(code, types.CodeType)
    assert code.co_filename == "main.py"
    locals_ = _collect_local_names(code)
    assert "data_dir" not in locals_               # 混淆在加密之前已生效
    assert any(x.startswith("_o") for x in locals_)


# ---------------------------------------------------------------- 字符串加密构建链（§13.3③ S7）
_TEST_MAIN = '''\
"""entry stub."""
import json

import applocal

SECRET_TOKEN = "pkapp-secret-value-0123456789"


def deco(s):
    def wrap(fn):
        fn.route = s
        return fn
    return wrap


@deco("/api/v1/very-long-route-path")
async def helper(x="/default-long-value-xyz"):
    return "helper-return-long-plain-42"


async def app(scope, receive, send):
    if scope["type"] != "http":
        return
    if scope["path"] == "/api/hello":
        hit = helper.__name__ == "not-the-helper-name"
        await send({"type": "http.response.start", "status": 200,
                    "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body",
                    "body": json.dumps({"token": SECRET_TOKEN[:5],
                                        "hit": hit}).encode()})
        return
    await send({"type": "http.response.start", "status": 404,
                "headers": [(b"content-type", b"application/json")]})
    await send({"type": "http.response.body", "body": b'{"error": "not found"}'})
'''


def _const_strs(code):
    """递归收集 code 树全部 str 常量（含子 code 与容器——函数默认参数以元组
    形式存于父作用域 co_consts，不展开容器会漏判豁免串）。"""
    out = set()
    stack = [code]
    while stack:
        c = stack.pop()
        items = list(c.co_consts)
        while items:
            v = items.pop()
            if isinstance(v, types.CodeType):
                stack.append(v)
            elif isinstance(v, (tuple, frozenset, list)):
                items.extend(v)
            elif isinstance(v, str):
                out.add(v)
    return out


def _has_stub(code):
    stack = [code]
    while stack:
        c = stack.pop()
        if c.co_name == "_pkobf_d":
            return True
        stack.extend(v for v in c.co_consts if isinstance(v, types.CodeType))
    return False


def _const_bytes(code):
    """递归收集 code 树全部 bytes 常量（含子 code 与容器——3.12 编译器把模块级
    `_TBL = [b'..', ...]` 常量列表折叠成元组常量，不展开容器会漏掉全部密文）。
    bytes 不进 intern 表，marshal 写出不受进程全局态漂移影响，是双跑密文比对的
    稳定载体。"""
    out = set()
    stack = [code]
    while stack:
        c = stack.pop()
        items = list(c.co_consts)
        while items:
            v = items.pop()
            if isinstance(v, types.CodeType):
                stack.append(v)
            elif isinstance(v, (tuple, frozenset, list)):
                items.extend(v)
            elif isinstance(v, bytes):
                out.add(v)
    return out


def test_build_string_obfuscated(project, wheels_dir, tmp_path):
    """★§13.3③ S7★ 字符串加密层构建链：直值位 ≥16 长串进 _TBL 密文（原串不进
    co_consts），豁免串（装饰器参数/默认参数/短串）原样；G5 双跑 build 密文逐字节
    一致。

    ★G5 断法（设计预埋的稳妥断法）★：硬闸门是"同 key 同源 → 密文逐字节一致"，
    载体取 pyc 的 bytes 常量（bytes 不受 CPython intern/memo 全局态漂移影响）；
    整 pyc 字节级一致由生产子进程每跑新进程保证（且由无混淆的 G1 全 spk 比对
    覆盖）——进程内 fallback 连紧邻双跑也会因 rename 标识符进入全局 intern 表而
    漂移（实测），故不断言整 pyc。另做闭合环：从 obf.key 本地按 keystream 规格推
    算三条已知明文的期望密文，逐条在构建产物中命中。"""
    import marshal

    from pkapp.packager.obfuscate import keystream, xor_bytes

    with open(os.path.join(project, "app", "main.py"), "w", encoding="utf-8") as f:
        f.write(_TEST_MAIN)
    _enable_code_obfuscation(project)
    out1, out2 = str(tmp_path / "s1.spk"), str(tmp_path / "s2.spk")
    _build(project, wheels_dir, out1)
    _build(project, wheels_dir, out2)
    with zipfile.ZipFile(out1) as zf, zipfile.ZipFile(out2) as zf2:
        names = zf.namelist()
        pycs = {n: zf.read(n) for n in names
                if n.startswith("app/") and n.endswith(".pyc")}
        main_pyc = [n for n in pycs if "main" in n]
        assert len(main_pyc) == 1
        assert "app/main.py" in names              # 磁盘源码恒保留
        code = marshal.loads(pycs[main_pyc[0]][16:])    # 剥 16 字节 pyc 头
        code2 = marshal.loads(zf2.read(main_pyc[0])[16:])
        # G5①：双跑密文表（bytes 常量多重集）逐字节一致
        assert _const_bytes(code) == _const_bytes(code2)
    with open(os.path.join(project, "app", "main.py"), encoding="utf-8") as f:
        assert "pkapp-secret-value-0123456789" in f.read()
    strs = _const_strs(code)
    assert "pkapp-secret-value-0123456789" not in strs   # Assign 直值位已加密
    assert "helper-return-long-plain-42" not in strs     # Return 直值位已加密
    assert "not-the-helper-name" not in strs             # Compare 比较元已加密
    assert "/api/v1/very-long-route-path" in strs        # 装饰器参数豁免原样
    assert "/default-long-value-xyz" in strs             # 默认参数豁免原样
    assert "/api/hello" not in strs                      # ★P1.5★ 10 字符入加密面
    assert "token" in strs and "hit" in strs             # 短串（<8）原样
    assert _has_stub(code)                               # 惰性解密 stub 已注入
    assert any(x.startswith("_o") for x in _collect_local_names(code))
    # G5②闭合环：obf.key + keystream(key32, module_id=co_filename, len) 规格推算
    # 期望密文，逐条命中构建产物（keystream 独立性与 G5 双端口径同时验证）
    obf_key = bytes.fromhex(open(os.path.join(project, ".pkapp", "obf.key"),
                                 encoding="utf-8").read())
    ciphers = _const_bytes(code)
    for plain in ("pkapp-secret-value-0123456789", "helper-return-long-plain-42",
                  "not-the-helper-name"):
        raw = plain.encode("utf-8")
        assert xor_bytes(raw, keystream(obf_key, code.co_filename, len(raw))) in ciphers


def test_build_string_obfuscated_and_encrypted(project, wheels_dir, tmp_path,
                                               monkeypatch):
    """★混淆 + 字符串加密 + 代码加密三重叠加★：blob 解出的 code 同样无原长串、
    豁免串在位、stub 在位、局部名 _o*，删明文闸不回归。"""
    import marshal

    from pkapp.packager import keylib

    dll = keylib.locate_dll("windows")
    assert dll, "keylib/build/pkapp_key.dll 未编译（先跑 keylib/build.bat）"
    with open(os.path.join(project, "app", "main.py"), "w", encoding="utf-8") as f:
        f.write(_TEST_MAIN)
    _enable_code_obfuscation(project)
    _enable_code_encryption(project)
    out = str(tmp_path / "soe.spk")
    key = keylib.derive_k_app(_set_master(monkeypatch), "demo")
    _build(project, wheels_dir, out)
    with zipfile.ZipFile(out) as zf:
        names = zf.namelist()
        stage = str(tmp_path / "stage")
        zf.extractall(stage)
    # 删明文闸：混淆/字符串加密不改变加密链的删明文契约
    assert not any(n.endswith((".py", ".pyc")) or "__pycache__" in n
                   for n in names if n.startswith("app/"))
    assert "app/index.enc" in names
    patched = str(tmp_path / "pkapp_key.patched.dll")
    keylib.patch_dll(dll, patched, key)
    kl = keylib.KeyLib(patched)
    with open(os.path.join(stage, "app", keylib.blob_name("app.main")), "rb") as f:
        main_blob = f.read()
    code = marshal.loads(kl.decrypt("app.main", main_blob))
    assert code.co_filename == "main.py"
    strs = _const_strs(code)
    assert "pkapp-secret-value-0123456789" not in strs   # 字符串加密在加密之前已生效
    assert "/api/v1/very-long-route-path" in strs        # 路由路径合同豁免
    assert _has_stub(code)
    assert any(x.startswith("_o") for x in _collect_local_names(code))


# ---------------------------------------------------------------- RFT 跨模块统一改名（§4.1 P1）
_XMOD_MAIN = '''\
"""entry stub."""
import json

import app.pkg1 as p1
from app.pkg2 import combine


async def app(scope, receive, send):
    if scope["type"] != "http":
        return
    body = json.dumps({"r": p1.do_task(2), "c": combine(3, 4)}).encode()
    await send({"type": "http.response.start", "status": 200,
                "headers": [(b"content-type", b"application/json")]})
    await send({"type": "http.response.body", "body": body})
'''
_XMOD_PKG1 = "def do_task(x):\n    y = x * 10\n    return y + 1\n"
_XMOD_PKG2 = "def combine(a, b):\n    return a + b\n"


def test_build_xmod_rename_pipeline(project, wheels_dir, tmp_path):
    """★RFT★ 多模块构建链：build_rename_plan 全局改名 → pyc → 手工接线
    sys.modules（依赖先于 main）→ ASGI 直调行为等价 + 原符号清零 + G5 双跑一致。"""
    import asyncio
    import json
    import marshal
    import sys

    for rel, text in (("main.py", _XMOD_MAIN), ("pkg1.py", _XMOD_PKG1),
                      ("pkg2.py", _XMOD_PKG2)):
        with open(os.path.join(project, "app", rel), "w", encoding="utf-8") as f:
            f.write(text)
    _enable_code_obfuscation(project)
    out1, out2 = str(tmp_path / "x1.spk"), str(tmp_path / "x2.spk")
    _build(project, wheels_dir, out1)
    raws, pycs = {}, {}
    with zipfile.ZipFile(out1) as zf:
        for n in zf.namelist():
            # 仅混淆（无加密）→ app/ 恒保留源码 + __pycache__ checked-hash pyc
            if n.startswith("app/__pycache__/") and n.endswith(".pyc"):
                raws[n] = zf.read(n)
                pycs[n] = marshal.loads(raws[n][16:])       # 剥 16 字节 pyc 头
    assert set(pycs) == {
        "app/__pycache__/__init__.cpython-312.pyc",
        "app/__pycache__/main.cpython-312.pyc",
        "app/__pycache__/pkg1.cpython-312.pyc",
        "app/__pycache__/pkg2.cpython-312.pyc"}

    created = []
    try:
        for mid in ("app", "app.pkg1", "app.pkg2", "app.main"):
            m = types.ModuleType(mid)
            m.__package__ = mid
            if mid != "app.main":
                m.__path__ = []                             # 包语义（相对导入可解析）
            sys.modules[mid] = m
            created.append(mid)
        setattr(sys.modules["app"], "pkg1", sys.modules["app.pkg1"])
        setattr(sys.modules["app"], "pkg2", sys.modules["app.pkg2"])
        exec(pycs["app/__pycache__/pkg1.cpython-312.pyc"], sys.modules["app.pkg1"].__dict__)
        exec(pycs["app/__pycache__/pkg2.cpython-312.pyc"], sys.modules["app.pkg2"].__dict__)
        exec(pycs["app/__pycache__/main.cpython-312.pyc"], sys.modules["app.main"].__dict__)
        asgi = sys.modules["app.main"].app
        assert asgi.__name__ == "app"                       # entry 保护对：入口名不动
        msgs = []

        async def _receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def _send(m):
            msgs.append(m)

        asyncio.run(asgi({"type": "http", "path": "/x"}, _receive, _send))
        assert json.loads(msgs[-1]["body"]) == {"r": 21, "c": 7}
    finally:
        for mid in created:
            sys.modules.pop(mid, None)

    # 原符号清零：定义模块原名消失；main 链改写（attr 名进 co_names）
    assert "do_task" not in pycs["app/__pycache__/pkg1.cpython-312.pyc"].co_names
    assert "combine" not in pycs["app/__pycache__/pkg2.cpython-312.pyc"].co_names
    assert "do_task" not in pycs["app/__pycache__/main.cpython-312.pyc"].co_names
    l1 = _collect_local_names(pycs["app/__pycache__/pkg1.cpython-312.pyc"])
    l2 = _collect_local_names(pycs["app/__pycache__/pkg2.cpython-312.pyc"])
    assert "y" not in l1 and any(x.startswith("_o") for x in l1)
    assert {"a", "b"} <= l2                                 # 参数红线不动

    # G5：双跑 pyc 字节级一致
    _build(project, wheels_dir, out2)
    with zipfile.ZipFile(out2) as zf2:
        for n, raw in raws.items():
            assert zf2.read(n) == raw, f"G5: {n} 两跑不一致"
