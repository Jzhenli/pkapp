"""混淆层单测（§13 S1 改名/剥离 + §13.3③ S5/S6 keystream 与字符串加密）。

行为等价断言方式：同源码分别 compile 与 compile_obfuscated → 各 exec 到独立
命名空间 → 调用同名函数比对返回值；改名面用 code object 的
co_varnames/co_cellvars/co_freevars（局部名）+ co_names（全局/属性名）核对。
"""
import ast
import marshal
import types

import pytest

from pkapp.packager.obfuscate import (compile_obfuscated, keystream, transform,
                                      xor_bytes)


def _run(src, fname="f", *args, **kwargs):
    """行为等价：原码与混淆码各自 exec → 调同名函数，返回（原值, 混淆值, 统计）。"""
    ns1, ns2 = {}, {}
    exec(compile(src, "t.py", "exec"), ns1)
    code, stats = compile_obfuscated(src, "t.py")
    exec(code, ns2)
    return ns1[fname](*args, **kwargs), ns2[fname](*args, **kwargs), stats


def _funcs(code):
    """递归收集 code 及其子 code（按 co_name 索引，同名取全部）。"""
    out = [code]
    for c in code.co_consts:
        if isinstance(c, types.CodeType):
            out.extend(_funcs(c))
    return out


def _locals_of(code):
    """全部 code object 的局部名并集（varnames+cellvars+freevars，不含 co_names）。"""
    out = set()
    for c in _funcs(code):
        out.update(c.co_varnames)
        out.update(c.co_cellvars)
        out.update(c.co_freevars)
    return out


def _names_of(code):
    """全部 code object 的名字引用并集（co_names：全局/属性/keyword arg）。"""
    out = set()
    for c in _funcs(code):
        out.update(c.co_names)
    return out


# ---------------------------------------------------------------- 改名面
def test_local_var_renamed_to_o():
    src = "def f():\n    x = 41\n    return x + 1\n"
    orig, obf, stats = _run(src)
    assert orig == obf == 42
    assert stats["renamed"] == 1 and stats["stripped"] == 0
    code, _ = compile_obfuscated(src, "t.py")
    fc = [c for c in _funcs(code) if c.co_name == "f"][0]
    assert "x" not in fc.co_varnames
    assert any(n.startswith("_o") for n in fc.co_varnames)


def test_nested_function_name_renamed():
    src = "def outer():\n    def inner():\n        return 7\n    return inner() + 1\n"
    orig, obf, stats = _run(src, "outer")
    assert orig == obf == 8
    assert stats["renamed"] == 1
    code, _ = compile_obfuscated(src, "t.py")
    names = {c.co_name for c in _funcs(code)}
    assert "outer" in names                       # 模块级函数名不改
    assert not any(n == "inner" for n in names)   # 嵌套函数名已改
    assert any(n.startswith("_o") for n in names)


# ---------------------------------------------------------------- 白名单逐项不动
def test_whitelist_parameters():
    src = ("def f(x, y=2, *args, kw=3, **kw2):\n"
           "    z = x + y + len(args) + kw + kw2.get('k', 0)\n"
           "    return z\n")
    orig, obf, stats = _run(src, "f", 1, 2, 3, 4, kw=5, k=6)
    assert orig == obf == 1 + 2 + 2 + 5 + 6
    code, _ = compile_obfuscated(src, "t.py")
    fc = [c for c in _funcs(code) if c.co_name == "f"][0]
    assert fc.co_varnames[:5] == ("x", "y", "kw", "args", "kw2")  # 参数名是公开合同
    assert stats["renamed"] == 1                                  # 只有 z 改


def test_whitelist_class_body_names():
    src = ("def make():\n"
           "    v = 5\n"
           "    class C:\n"
           "        w = v + 1\n"
           "        def m(self):\n"
           "            u = 2\n"
           "            return self.w + u\n"
           "    return C().m()\n")
    orig, obf, stats = _run(src, "make")
    assert orig == obf == 8
    code, _ = compile_obfuscated(src, "t.py")
    # 类体内名（w/m）与属性访问（self.w 的 w）不动；v/u/C（make 的局部绑定）照改
    assert {"m", "w"} <= _names_of(code)
    assert "C" not in _names_of(code)
    assert "v" not in _locals_of(code) and "u" not in _locals_of(code)
    assert any(n.startswith("_o") for n in _locals_of(code))


def test_whitelist_global_decl():
    src = "G = 0\n\ndef f():\n    global G\n    G = G + 1\n    return G\n"
    orig, obf, stats = _run(src)
    assert orig == obf == 1
    code, _ = compile_obfuscated(src, "t.py")
    assert "G" in _names_of(code)
    assert stats["renamed"] == 0


def test_whitelist_import_binding():
    src = ("def f():\n"
           "    import json\n"
           "    from math import sqrt\n"
           "    return json.dumps([1]) + str(sqrt(4))\n")
    orig, obf, stats = _run(src)
    assert orig == obf == "[1]2.0"
    code, _ = compile_obfuscated(src, "t.py")
    names = _names_of(code)
    assert "json" in names and "sqrt" in names    # import 绑定名不改
    assert stats["renamed"] == 0


def test_whitelist_dunder_and_module_names():
    src = ('M = 3\n_PRIV = 4\n\n'
           'def f():\n    __dunder__ = M + _PRIV\n    return __dunder__\n')
    orig, obf, stats = _run(src)
    assert orig == obf == 7
    code, _ = compile_obfuscated(src, "t.py")
    assert "__dunder__" in _locals_of(code)       # dunder 不改
    assert "M" in _names_of(code) and "_PRIV" in _names_of(code)  # 模块级名（含 _x）不改
    assert stats["renamed"] == 0


def test_whitelist_callside_keyword_arg():
    src = ("def f(a, b=0):\n    return a + b\n\n"
           "def g():\n    return f(a=1, b=2)\n")
    orig, obf, stats = _run(src, "g")
    assert orig == obf == 3
    code, _ = compile_obfuscated(src, "t.py")
    gc = [c for c in _funcs(code) if c.co_name == "g"][0]
    # 3.12 调用侧关键字名在 co_consts 名元组（非 co_names）——原样保留
    assert ("a", "b") in gc.co_consts


def test_whitelist_protected_names():
    tree = ast.parse("def f():\n    keep = 1\n    drop = 2\n    return keep + drop\n")
    tree2, stats = transform(tree, "t.py", protected=frozenset({"keep"}))
    assert stats["renamed"] == 1                  # 只 drop 改
    assert "keep" in ast.dump(tree2)


# ---------------------------------------------------------------- 坑位与两端一致
def test_closure_free_var_consistent():
    src = ("def f():\n"
           "    x = 5\n"
           "    def inner():\n"
           "        return x + 1\n"
           "    return inner()\n")
    orig, obf, stats = _run(src)
    assert orig == obf == 6
    code, _ = compile_obfuscated(src, "t.py")
    outer = [c for c in _funcs(code) if c.co_name == "f"][0]
    inner = [c for c in _funcs(code) if c.co_name.startswith("_o")][0]
    assert any(n.startswith("_o") for n in outer.co_cellvars)   # 外层 cell 改名
    assert inner.co_freevars == outer.co_cellvars               # 两端一致


def test_nonlocal_consistent():
    src = ("def f():\n"
           "    c = 0\n"
           "    def inc():\n"
           "        nonlocal c\n"
           "        c += 1\n"
           "    inc()\n"
           "    inc()\n"
           "    return c\n")
    orig, obf, stats = _run(src)
    assert orig == obf == 2
    code, _ = compile_obfuscated(src, "t.py")
    outer = [c for c in _funcs(code) if c.co_name == "f"][0]
    inner = [c for c in _funcs(code) if c.co_name.startswith("_o")][0]
    assert inner.co_freevars == outer.co_cellvars               # nonlocal 两端一致


def test_genexpr_outer_ref():
    src = "def f():\n    base = 10\n    return sum(base + i for i in range(3))\n"
    orig, obf, stats = _run(src)
    assert orig == obf == 33                       # genexpr 引外层 free var（is_free → 父链查找）


def test_p709_inline_comprehension_target():
    src = ("def f(n):\n"
           "    total = sum(k * 2 for k in range(n))\n"
           "    ys = [k + 1 for k in range(3)]\n"
           "    return total, ys\n")
    orig, obf, stats = _run(src, "f", 3)
    assert orig == obf == (6, [1, 2, 3])
    code, _ = compile_obfuscated(src, "t.py")
    assert "k" not in _locals_of(code)             # 3.12 内联：目标即外层 local，照改


def test_except_as_renamed_and_implicit_del():
    src = ("def f():\n"
           "    try:\n"
           "        raise ValueError('boom')\n"
           "    except ValueError as e:\n"
           "        msg = str(e)\n"
           "    try:\n"
           "        e\n"
           "        return 'leaked'\n"
           "    except NameError:\n"
           "        return msg\n")
    orig, obf, stats = _run(src)
    assert orig == obf == "boom"                   # except-as 改名 + 块尾隐式 del 无 NameError
    code, _ = compile_obfuscated(src, "t.py")
    assert "e" not in _locals_of(code) and "msg" not in _locals_of(code)


def test_del_statement():
    src = ("def f():\n"
           "    x = 1\n"
           "    del x\n"
           "    try:\n"
           "        x\n"
           "        return 'bad'\n"
           "    except NameError:\n"
           "        return 'ok'\n")
    orig, obf, stats = _run(src)
    assert orig == obf == "ok"                     # Del ctx 与 Store/Load 同映射
    assert "x" not in _locals_of(compile_obfuscated(src, "t.py")[0])


def test_walrus_target():
    src = ("def f():\n"
           "    if (n := 10) > 5:\n"
           "        return n + 1\n"
           "    return 0\n")
    orig, obf, stats = _run(src)
    assert orig == obf == 11
    assert "n" not in _locals_of(compile_obfuscated(src, "t.py")[0])


def test_walrus_in_comprehension():
    src = ("def g():\n"
           "    ys = [(w := i) for i in range(3)]\n"
           "    return ys, w\n")
    orig, obf, stats = _run(src, "g")
    assert orig == obf == ([0, 1, 2], 2)           # walrus target 绑定在外层函数 scope
    assert "w" not in _locals_of(compile_obfuscated(src, "t.py")[0])


def test_zero_arg_super_class_cell():
    src = ("class A:\n"
           "    def greet(self):\n"
           "        return 'A'\n\n"
           "class B(A):\n"
           "    def greet(self):\n"
           "        return 'B+' + super().greet()\n")

    def call(program):
        ns = {}
        exec(program if isinstance(program, types.CodeType)
             else compile(program, "t.py", "exec"), ns)
        return ns["B"]().greet()

    code, _st = compile_obfuscated(src, "t.py")
    assert call(src) == call(code) == "B+A"        # __class__ cell（dunder 豁免）两端自然一致
    assert "A" in _names_of(code)


def test_recursive_escape_exempt():
    src = ("def outer():\n"
           "    def f():\n"
           "        return f\n"
           "    return f() is f\n")
    orig, obf, stats = _run(src, "outer")
    assert orig is obf is True
    code, _ = compile_obfuscated(src, "t.py")
    names = {c.co_name for c in _funcs(code)}
    assert "f" in names                            # 逃逸豁免：return 自身名 → 函数名不改
    assert not any(n.startswith("_o") for n in names)
    assert stats["renamed"] == 0


def test_yield_self_escape_exempt():
    src = ("def outer():\n"
           "    def gen():\n"
           "        yield gen\n"
           "    return list(gen()) == [gen]\n")
    orig, obf, stats = _run(src, "outer")
    assert orig is obf is True
    assert {c.co_name for c in _funcs(compile_obfuscated(src, "t.py")[0])} \
        & {"gen"} != set()


def test_param_shadowing_not_renamed_through():
    src = ("def f():\n"
           "    x = 1\n"
           "    def g(x):\n"          # 参数 x 遮蔽外层 x —— 体内 x 绝不穿透改名
           "        return x + 10\n"
           "    return x, g(5)\n")
    orig, obf, stats = _run(src)
    assert orig == obf == (1, 15)


# ---------------------------------------------------------------- 行为等价（批量）
@pytest.mark.parametrize("src,call,expect", [
    ("def f(a, b):\n    r = a * b\n    return r - 1\n", (3, 4), 11),
    ("def f():\n    xs = {i % 3 for i in range(7)}\n    return sorted(xs)\n", (), [0, 1, 2]),
    ("def f():\n    d = {k: k * k for k in range(3)}\n    return d[2]\n", (), 4),
    ("def f():\n"
     "    match [1, 2, 3]:\n"
     "        case [x, *rest]:\n"
     "            return x, rest\n", (), (1, [2, 3])),
])
def test_behavior_equivalence(src, call, expect):
    orig, obf, _st = _run(src, "f", *call)
    assert orig == obf == expect


# ---------------------------------------------------------------- 行号
def test_lineno_preserved_no_docstring():
    src = "def f(a):\n    b = a + 1\n    c = b * 2\n    return c\n"
    plain = compile(src, "t.py", "exec")
    obf, _st = compile_obfuscated(src, "t.py")
    lines = lambda c: {ln for _s, _e, ln in c.co_lines() if ln is not None}
    assert lines(plain) == lines(obf)              # 保留语句 lineno 集合逐点一致


def test_lineno_preserved_with_docstring_strip():
    src = 'def f():\n    """doc line1\n    line2"""\n    return 7\n'
    plain = compile(src, "t.py", "exec")
    obf, stats = compile_obfuscated(src, "t.py")
    lines = lambda c: {ln for _s, _e, ln in c.co_lines() if ln is not None}
    for fp, fo in zip(_funcs(plain), _funcs(obf)):  # 逐 code 对象比对
        assert lines(fo) <= lines(fp)               # 被删语句行段消失属预期
    fc = [c for c in _funcs(obf) if c.co_name == "f"][0]
    assert lines(fc) == {1, 4}                      # 保留语句（def 行/return 行）lineno 不变
    assert stats["stripped"] == 1
    ns = {}
    exec(obf, ns)
    assert ns["f"]() == 7


def test_co_filename_preserved():
    code, _st = compile_obfuscated("X = 1\n", "app/main.py")
    assert code.co_filename == "app/main.py"


# ---------------------------------------------------------------- docstring 四规则
def test_docstring_rules_and_counts():
    src = ('"""module doc"""\n'
           'import json\n\n\n'
           'def plain():\n'
           '    """plain doc"""\n'
           '    return 1\n\n\n'
           '@app.get("/")\n'
           'def routed():\n'
           '    """route doc"""\n'
           '    return 2\n\n\n'
           'def doctestish():\n'
           '    """Example:\n'
           '    >>> 1 + 1\n'
           '    2\n'
           '    """\n'
           '    return 3\n\n\n'
           'class Model:\n'
           '    """model doc"""\n'
           '    x: int = 1\n')
    tree = ast.parse(src)
    tree2, stats = transform(tree, "t.py")
    dump = ast.dump(tree2)
    assert "module doc" not in dump                # 模块 docstring 剥
    assert "plain doc" not in dump                 # 无装饰器函数剥
    assert "route doc" in dump                     # 带装饰器豁免（FastAPI OpenAPI）
    assert 'Constant(value="doc line' not in dump
    assert "Example:" in dump                      # 含 >>> 豁免（doctest）
    assert "model doc" in dump                     # class 豁免（pydantic description）
    assert stats["stripped"] == 2
    assert stats["renamed"] == 0


# ---------------------------------------------------------------- 确定性
def test_transform_deterministic():
    src = ("def f(a):\n"
           "    x = a + 1\n"
           "    def g():\n"
           "        return x * 2\n"
           "    return g()\n")
    t1, s1 = transform(ast.parse(src), "t.py")
    t2, s2 = transform(ast.parse(src), "t.py")
    assert ast.dump(t1, include_attributes=False) == \
        ast.dump(t2, include_attributes=False)
    assert s1 == s2 == {"renamed": 2, "stripped": 0}


def test_compile_obfuscated_marshal_roundtrip():
    code, stats = compile_obfuscated("def f():\n    v = 3\n    return v * 2\n",
                                     "app/main.py")
    assert isinstance(code, types.CodeType)
    blob = marshal.dumps(code)
    back = marshal.loads(blob)
    ns = {}
    exec(back, ns)
    assert ns["f"]() == 6
    assert stats["renamed"] == 1


# ---------------------------------------------------------------- FastAPI 小树契约（纯 AST，不 import fastapi）
def test_fastapi_tree_contract():
    src = ('from fastapi import FastAPI, Depends\n'
           'from pydantic import BaseModel\n\n'
           'app = FastAPI()\n\n\n'
           'def get_db():\n'
           '    return {"db": True}\n\n\n'
           'class Item(BaseModel):\n'
           '    """Item schema."""\n'
           '    name: str\n'
           '    price: float = 0.0\n\n\n'
           '@app.get("/items/{item_id}")\n'
           'def read_item(item_id: int, db=Depends(get_db)):\n'
           '    """Read one item."""\n'
           '    q = item_id * 2\n'
           '    return {"item_id": q, "db": db}\n')
    tree2, stats = transform(ast.parse(src), "app/main.py")
    dump = ast.dump(tree2)
    # 装饰器参数串 / 路由函数名 / 其 docstring / 类字段名 全部原样
    assert "'/items/{item_id}'" in dump
    assert "read_item" in dump and "Read one item." in dump
    assert "Item" in dump and "Item schema." in dump
    assert "'name'" in dump and "price" in dump
    assert "get_db" in dump and "Depends" in dump
    assert "item_id" in dump                       # 参数名不改
    # 模块级名/类名不动 → renamed 只来自路由函数体局部 q
    assert stats["renamed"] == 1 and stats["stripped"] == 0
    code = compile(tree2, "app/main.py", "exec")
    fc = [c for c in _funcs(code) if c.co_name == "read_item"][0]
    assert "q" not in fc.co_varnames
    assert any(n.startswith("_o") for n in fc.co_varnames)


# ---------------------------------------------------------------- 期2：keystream（§13.3③ S5）
def test_keystream_deterministic_and_independent():
    import hashlib

    k1, k2 = bytes(range(32)), bytes(range(32))[::-1]
    # G5：同 (key32, module_id) → 同流；改任一派生输入 → 流变（独立性）
    assert keystream(k1, "app.main", 100) == keystream(k1, "app.main", 100)
    assert keystream(k1, "app.main", 100) != keystream(k2, "app.main", 100)
    assert keystream(k1, "app.main", 100) != keystream(k1, "app.other", 100)
    # 分块向量：SHA256(key‖mid‖counter_u32_be) 逐块（32B）拼接截断，counter 从 0 大端
    h = lambda c: hashlib.sha256(k1 + b"app.main" + c.to_bytes(4, "big")).digest()
    assert keystream(k1, "app.main", 64) == h(0) + h(1)
    assert keystream(k1, "app.main", 33) == h(0) + h(1)[:1]      # 截断
    assert keystream(k1, "m", 0) == b""
    assert xor_bytes(b"\x01\x02", b"\x03\x07") == b"\x02\x05"


# ---------------------------------------------------------------- 期2：字符串加密 pass（§13.3③ S6）
_KEY = bytes(range(32))


def test_strings_replace_four_direct_slots():
    """替换面：Expr 语句 / Assign value / Return value / Compare 比较元 各一，
    ≥16 长串 → _pkobf_d(idx)（idx 按收集序），行为等价由 stub 自解密保证。"""
    src = ('A = "assign-value-long-string-001"\n'
           'def f():\n'
           '    return "return-value-long-string2"\n'
           'B = ("x" == "compare-operand-long-003")\n'
           '"expr-stmt-long-string-000004"\n')
    tree, stats = transform(ast.parse(src), "app/main.py",
                            string_key=_KEY, module_id="main.py")
    assert stats["strings"] == 4
    dump = ast.dump(tree)
    for s in ("assign-value-long-string-001", "return-value-long-string2",
              "compare-operand-long-003", "expr-stmt-long-string-000004"):
        assert s not in dump                      # 明文已替换为密文表取用
    for i in range(4):
        assert f"Constant(value={i})" in dump     # idx 按收集序
    assert dump.count("_pkobf_d") == 4 + 1        # 4 个替换点 + 1 个 stub def
    # 行为等价：exec 后经 stub 解密取回原串
    ns = {}
    exec(compile(tree, "app/main.py", "exec"), ns)
    assert ns["A"] == "assign-value-long-string-001"
    assert ns["f"]() == "return-value-long-string2"
    assert ns["B"] is False
    assert all(isinstance(x, str) for x in ns["_TBL"])   # 全部解密回写明文


def test_stub_lazy_decrypt_once():
    """stub 惰性：首次调用解密并回写 _TBL[i]（bytes → str），二次命中缓存。"""
    src = 'def f():\n    return "lazy-decrypt-long-string-01"\n'
    code, stats = compile_obfuscated(src, "app/main.py", string_key=_KEY,
                                     module_id="main.py")
    assert stats["strings"] == 1
    assert any(c.co_name == "_pkobf_d" for c in _funcs(code))   # stub 已注入
    ns = {}
    exec(code, ns)
    tbl = ns["_TBL"]
    assert isinstance(tbl[0], bytes)              # 未调用前保持密文
    assert ns["f"]() == "lazy-decrypt-long-string-01"
    assert isinstance(tbl[0], str)                # 首次调用即回写明文（缓存）
    assert ns["f"]() == "lazy-decrypt-long-string-01"   # 二次命中缓存


def test_strings_exempt_faces():
    """豁免面逐项原样（从严）：__all__/f-string/短串/bytes/装饰器参数/默认参数/
    参数与返回注解/函数与 class docstring 位置/match pattern/模块 docstring（>>>）。"""
    src = (
        '"""module: >>> doctest keep"""\n'
        '__all__ = ["exported-name-long-string-01"]\n'
        'FS = f"fstring-joined-long-value-002"\n'
        'SHORT = "short<16"\n'
        'BY = b"bytes-long-value-0000003"\n'
        'def deco(s):\n'
        '    def w(fn):\n'
        '        fn.tag = s\n'
        '        return fn\n'
        '    return w\n'
        '@deco("/decorator-route-long-path-04")\n'
        'def g(x="/default-arg-long-value-05", y: "ann-arg-type-long-06" = 2) \\\n'
        '        -> "ann-return-long-0007":\n'
        '    """func doc long not business8"""\n'
        '    return None\n'
        'def m(v):\n'
        '    match v:\n'
        '        case "match-pattern-long-string9":\n'
        '            return 1\n'
        '    return 0\n'
        'class C:\n'
        '    """class doc long not business0"""\n'
        '    pass\n')
    tree, stats = transform(ast.parse(src), "app/main.py",
                            string_key=_KEY, module_id="main.py")
    assert stats["strings"] == 0                  # 豁免面零命中
    dump = ast.dump(tree)
    assert "_pkobf_d" not in dump                 # 零命中不注入 stub
    for s in ("exported-name-long-string-01",           # __all__
              "fstring-joined-long-value-002",          # f-string 整体
              "short<16",                               # 短串（<16）
              "bytes-long-value-0000003",               # bytes
              "/decorator-route-long-path-04",          # 装饰器参数
              "/default-arg-long-value-05",             # 默认参数
              "ann-arg-type-long-06",                   # 参数注解
              "ann-return-long-0007",                   # 返回注解
              "func doc long not business8",            # 函数 docstring 位置
              "match-pattern-long-string9",             # match pattern
              "class doc long not business0",           # class docstring 位置
              "module: >>> doctest keep"):              # 模块 docstring（>>>）
        assert s in dump, s


def test_strings_behavior_equivalence():
    """行为等价（含字符串比较）：混淆 exec 产物与原源码语义一致。"""
    src = ('def check(v):\n'
           '    if v == "expect-eq-long-operand-1":\n'
           '        return "yes-return-long-plain-2"\n'
           '    return "no-return-long-plain-03"\n'
           'R = check("expect-eq-long-operand-1")\n')
    ns1 = {}
    exec(compile(src, "t.py", "exec"), ns1)
    code, stats = compile_obfuscated(src, "app/main.py", string_key=_KEY,
                                     module_id="main.py")
    ns2 = {}
    exec(code, ns2)
    assert stats["strings"] == 3                  # 比较元 + 两个 return
    assert ns1["R"] == ns2["R"] == "yes-return-long-plain-2"
    assert ns2["check"]("other") == "no-return-long-plain-03"


def test_strings_g5_deterministic():
    """G5：同 key 同 module_id 双跑 compile_obfuscated → pyc 组装字节一致；
    换 key → pyc 必变。注意：两次 compile 之间不得 exec——exec 会改变解释器
    intern/memo 历史，进程内 marshal 字节即漂移（生产子进程每跑新进程免疫）。"""
    from importlib._bootstrap_external import _code_to_hash_pyc
    from importlib.util import source_hash

    src = 'V = "deterministic-long-string-001"\n'
    runs = [compile_obfuscated(src, "app/main.py", string_key=_KEY,
                               module_id="main.py") for _ in range(2)]
    assert runs[0][1] == runs[1][1] == {"renamed": 0, "stripped": 0, "strings": 1}
    pycs = [_code_to_hash_pyc(c, source_hash(b"x"), checked=True)
            for c, _st in runs]
    assert pycs[0] == pycs[1]
    other, _st = compile_obfuscated(src, "app/main.py",
                                    string_key=bytes(range(1, 33)),
                                    module_id="main.py")
    assert _code_to_hash_pyc(other, source_hash(b"x"), checked=True) != pycs[0]


def test_stub_name_conflict_rejected():
    """业务源码以标识符形态占用 _TBL/_pkobf_d → ValueError（极端保守）。"""
    with pytest.raises(ValueError, match="_TBL"):
        compile_obfuscated('_TBL = "conflict-long-string-01"\n', "t.py",
                           string_key=_KEY, module_id="m")
    with pytest.raises(ValueError, match="_pkobf_d"):
        compile_obfuscated('def _pkobf_d(i):\n    return "long-enough-string-02"\n',
                           "t.py", string_key=_KEY, module_id="m")


def test_stub_local_shadow_resolved_by_rename():
    """函数局部 _TBL 被改名 pass 消化 → 与 stub 全局名无冲突（冲突检查在改名后）。"""
    src = 'def f():\n    _TBL = "local-shadow-long-string"\n    return _TBL\n'
    code, stats = compile_obfuscated(src, "t.py", string_key=_KEY, module_id="m")
    assert stats["renamed"] == 1 and stats["strings"] == 1
    ns = {}
    exec(code, ns)
    assert ns["f"]() == "local-shadow-long-string"


def test_strings_pass_disabled_without_key():
    """期1 调用方（不传 string_key/module_id）行为不变、stats 无 strings 键。"""
    src = 'V = "long-string-not-encrypted-here"\n'
    code, stats = compile_obfuscated(src, "t.py")
    assert "strings" not in stats
    ns = {}
    exec(code, ns)
    assert ns["V"] == "long-string-not-encrypted-here"
    assert not any(c.co_name == "_pkobf_d" for c in _funcs(code))


# ---------------------------------------------------------------- review 修复回归
def test_escape_forward_reference_sibling():                # OB-1①
    """★OB-1★ 前向引用兄弟：豁免 def 在后、引用在前——豁免判定已前移到
    阶段一（候选分配即排除），先前语句的引用不会被改写后悬空成 NameError。"""
    src = ("def outer():\n"
           "    def get():\n"
           "        return handler.__name__\n"
           "    def handler():\n"
           "        return handler\n"                       # 裸名自引用 → 豁免
           "    return get()\n")
    orig, obf, stats = _run(src, "outer")
    assert orig == obf == "handler"                         # 行为等价（无悬空引用）
    code, _ = compile_obfuscated(src, "t.py")
    names = {c.co_name for c in _funcs(code)}
    assert "handler" in names                               # 豁免名整体保留
    assert "get" not in names                               # 非豁免照常改名
    assert stats["renamed"] == 1


def test_escape_redefinition_stays_consistent():            # OB-1②
    """★OB-1★ 同名重定义：其一豁免 → 该名在定义所在 scope 整体不改——两个 def
    与全部引用一致保持原名（visit 时才 del 会造成 split-binding / 静默错函数）。"""
    src = ("def outer():\n"
           "    def f():\n"
           "        return f\n"                             # 裸名自引用 → 豁免
           "    def f():\n"
           "        return 42\n"                            # 重定义非豁免 → 同名连带保持
           "    return f()\n")
    orig, obf, stats = _run(src, "outer")
    assert orig == obf == 42
    code, _ = compile_obfuscated(src, "t.py")
    assert {c.co_name for c in _funcs(code)} == {"<module>", "outer", "f"}   # 无 _o* 分裂
    assert stats["renamed"] == 0


def test_escape_call_form_still_renamed():                  # OB-1③
    """★OB-1★ Call 型 return rec(n-1) 不豁免（非裸名自引用）→ 仍改名且行为一致；
    与裸名 return 豁免（现有用例）形成对照。"""
    src = ("def outer():\n"
           "    def rec(n):\n"
           "        return 1 if n <= 1 else rec(n - 1)\n"   # Call 型 → 不豁免
           "    return rec(5)\n")
    orig, obf, stats = _run(src, "outer")
    assert orig == obf == 1
    code, _ = compile_obfuscated(src, "t.py")
    names = {c.co_name for c in _funcs(code)}
    assert "rec" not in names and "outer" in names
    assert any(n.startswith("_o") for n in names)
    assert stats["renamed"] == 1


def test_obf_compile_bom_and_declared_encoding(tmp_path):   # OB-2
    """★OB-2★ obf 编译分支解码与 py_compile 同语义（tokenize.detect_encoding）：
    带 BOM / 声明 gbk 的源码经回退路径全链编译不炸（硬 utf-8 会当乱码炸掉）。"""
    from pkapp.packager.assemble import _compile_checked_hash

    root = tmp_path / "app"
    root.mkdir()
    # 嵌套局部绑定让改名 pass 也有产出——解码正确性 + 混淆管线双验证
    (root / "bom.py").write_bytes(
        '\ufeffdef get():\n    x = 1\n    return x + 1\n'.encode("utf-8"))
    (root / "gbk.py").write_bytes(
        "# -*- coding: gbk -*-\n"
        'def gbk_fn():\n    y = 2\n    return y * 2\n'.encode("gbk"))
    st = _compile_checked_hash(str(root), obfuscate=True, obf_key=bytes(range(32)))
    assert st["renamed"] == 2 and st["strings"] == 0        # 走通即解码正确


def test_stub_conflict_import_forms():                      # OB-3
    """★OB-3★ import 形态的 stub 名占用也拒绝：asname 优先；无 asname 时首段/
    尾段任一命中即 ValueError（import a._TBL 绑定实为 a，误拒可接受——改写
    asname 即绕过）；普通导入与 asname 改绑不误伤。"""
    key = _KEY
    for src in ("import _TBL\n",
                "import a as _TBL\n",
                "from pkg import _TBL\n",
                "import a._TBL\n"):                          # 尾段命中，保守误拒
        with pytest.raises(ValueError, match="stub 名"):
            compile_obfuscated(src, "t.py", string_key=key, module_id="m")
    for src in ("import _TBL as x\n",                        # asname=x 不占用
                "import a\n",                                # 普通导入
                "from pkg import a\n",
                "import a.b.c\n"):                           # 首尾段均不命中
        compile_obfuscated(src, "t.py", string_key=key, module_id="m")   # 不抛即可
