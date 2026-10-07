"""混淆层单测（§13 S1 改名/剥离 + §13.3③ S5/S6 keystream 与字符串加密）。

行为等价断言方式：同源码分别 compile 与 compile_obfuscated → 各 exec 到独立
命名空间 → 调用同名函数比对返回值；改名面用 code object 的
co_varnames/co_cellvars/co_freevars（局部名）+ co_names（全局/属性名）核对。
"""
import ast
import marshal
import types

import pytest

from pkapp.packager.obfuscate import (_module_id_for, build_rename_plan,
                                      compile_obfuscated, keystream,
                                      transform, xor_bytes)


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


# ---------------------------------------------------------------- 认领对齐固化（M2）
def test_genexpr_nested_claim_alignment():
    """M2 固化：嵌套 genexpr——内外两层推导式的 symtable 块认领逐层对齐，
    scope 栈跟随 AST 结构不串块，行为等价、目标名照改。"""
    src = "def f(z):\n    return sum(x for x in (y for y in z))\n"
    orig, obf, stats = _run(src, "f", [1, 2, 3])
    assert orig == obf == 6
    code, _ = compile_obfuscated(src, "t.py")
    assert "x" not in _locals_of(code) and "y" not in _locals_of(code)


def test_genexpr_sibling_claim_alignment():
    """M2 固化：同型兄弟 genexpr ×2——第二个同型块不得误认领第一个的块
    （异名 x/y 双双改净 = 认领逐块对齐的直接证据）。"""
    src = ("def f(z):\n"
           "    a = sum(x for x in z)\n"
           "    b = sum(y for y in z)\n"
           "    return a + b\n")
    orig, obf, stats = _run(src, "f", [1, 2, 3])
    assert orig == obf == 12
    code, _ = compile_obfuscated(src, "t.py")
    assert "x" not in _locals_of(code) and "y" not in _locals_of(code)


def test_lambda_genexpr_claim_alignment():
    """M2 固化：lambda + genexpr 混合——lambda 块与其内 genexpr 块两层认领，
    参数名 s 合同不动，genexpr 目标 v（3.12 内联 = lambda 局名）照改。"""
    src = ("def f(z):\n"
           "    g = lambda s: sum(v for v in s)\n"
           "    return g(z) + g(z)\n")
    orig, obf, stats = _run(src, "f", [1, 2, 3])
    assert orig == obf == 12
    code, _ = compile_obfuscated(src, "t.py")
    assert "v" not in _locals_of(code)
    fc = [c for c in _funcs(code) if c.co_varnames[:1] == ("s",)][0]
    assert "s" in fc.co_varnames                   # 参数名是公开合同，不动


def test_default_arg_genexpr_claim_alignment():
    """M2 固化：默认参位 genexpr——默认值在外层 scope 求值（def 时一次性），
    genexpr 块认领挂到外层块（而非 def 的函数块），改名两端一致行为等价。"""
    src = ("def make():\n"
           "    def f(z, gen=tuple(i * 2 for i in range(3))):\n"
           "        return list(gen) + [z]\n"
           "    return f\n")
    ns1 = {}
    exec(compile(src, "t.py", "exec"), ns1)
    assert ns1["make"]()(7) == [0, 2, 4, 7]
    code, stats = compile_obfuscated(src, "t.py")
    ns2 = {}
    exec(code, ns2)
    assert ns2["make"]()(7) == [0, 2, 4, 7]
    assert "i" not in _locals_of(code)             # genexpr 目标照改（认领对齐）


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
    assert s1 == s2                              # G5 全字典一致（含 ledger）
    assert s1["renamed"] == 2 and s1["stripped"] == 0


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
        'SHORT = "sh<8"\n'
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
              "sh<8",                                   # 短串（<8）
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


def test_min_str_boundary_p15():
    """★P1.5★ _MIN_STR 16→8：8 字符串入加密面，7 字符串仍原样
    （forbidden 禁换集防同串断裂机制不变，豁免面照旧）。"""
    src = 'A = "len-7!!"\nB = "len-8!!!"\nC = "len-9!!!!"\n'
    assert len("len-7!!") == 7 and len("len-8!!!") == 8 and len("len-9!!!!") == 9
    tree, stats = transform(ast.parse(src), "app/main.py",
                            string_key=_KEY, module_id="main.py")
    assert stats["strings"] == 2                  # 8/9 入加密面
    dump = ast.dump(tree)
    assert "len-7!!" in dump                      # 7 仍原样
    assert "len-8!!!" not in dump and "len-9!!!!" not in dump


# ---------------------------------------------------------------- M1 值位递归下钻
def test_strings_recursive_value_positions():
    """★M1★ 递归下钻：容器元素（list/tuple/set/dict 值）、Call 实参（含
    keyword 值与嵌套调用内层）、BinOp 拼接、Subscript 取值位——全部密文化。"""
    src = ('L = ["list-elem-long-string-001", "list-elem-long-string-002"]\n'
           'T = ("tuple-elem-long-string3",)\n'
           'S = {"set-elem-long-string-004"}\n'
           'D = {"dk-long-string-000005": "dv-long-string-00006"}\n'
           'def log(msg, prefix=""):\n'
           '    return prefix + msg\n'
           'C = log("call-arg-long-string-00006", prefix="kw-value-long-str07")\n'
           'N = log(log("nested-inner-long-str08"))\n'
           'B = "binop-left-long-string-09" + "binop-right-long-010"\n'
           'X = D["dk-long-string-000005"]\n'
           'Y = D.get("dk-long-string-000005")\n')
    tree, stats = transform(ast.parse(src), "app/main.py",
                            string_key=_KEY, module_id="main.py")
    assert stats["strings"] == 11                 # 唯一串数（key 位 3 处复用 1 条目）
    dump = ast.dump(tree)
    for s in ("list-elem-long-string-001", "tuple-elem-long-string3",
              "set-elem-long-string-004", "dv-long-string-00006",
              "call-arg-long-string-00006", "kw-value-long-str07",
              "nested-inner-long-str08", "binop-left-long-string-09",
              "binop-right-long-010", "dk-long-string-000005"):
        assert s not in dump, s                   # 明文零残留（含 dict key 位）
    ns1 = {}
    exec(compile(src, "t.py", "exec"), ns1)
    ns2 = {}
    exec(compile(tree, "app/main.py", "exec"), ns2)
    for k in ("L", "T", "S", "D", "C", "N", "B", "X", "Y"):
        assert ns2[k] == ns1[k], k                # 行为等价（逐项同值）


def test_strings_dict_key_and_lookup_consistency():
    """★M1★ dict key 纳入替换：key 位与 .get/下标取值位同串同条目（counter
    复用）→ 构建期/运行期等值域一致，查找不断裂。"""
    src = ('TBL = {"perm-admin-users-00001": 1, "perm-audit-logs-000002": 2}\n'
           'def check(k):\n'
           '    return TBL.get(k, 0) + (TBL[k] if k in TBL else 0)\n'
           'R1 = check("perm-admin-users-00001")\n'
           'R2 = check("perm-missing-key-000003")\n')
    tree, stats = transform(ast.parse(src), "app/main.py",
                            string_key=_KEY, module_id="main.py")
    assert stats["strings"] == 3                  # 三个唯一串（首个 key 两处复用）
    ns1 = {}
    exec(compile(src, "t.py", "exec"), ns1)
    ns2 = {}
    exec(compile(tree, "app/main.py", "exec"), ns2)
    assert ns2["R1"] == ns1["R1"] == 2            # 命中：get + 下标双路一致
    assert ns2["R2"] == ns1["R2"] == 0            # 未命中路径不受密文化影响
    assert ns2["check"]("perm-audit-logs-000002") == 4   # get 2 + 下标 2，与原码一致


def test_strings_route_perms_encrypted():
    """★M1★ ROUTE_PERMS 型常量表（长权限串列表）已被密文化：明文零残留、
    成员判断行为等价（调用点实参与列表元素同串复用同条目）。"""
    perms = ["/admin/users/list/all/0001", "/audit/logs/export/x/002",
             "/billing/invoices/download/03"]
    src = ('ROUTE_PERMS = [\n'
           '    "/admin/users/list/all/0001",\n'
           '    "/audit/logs/export/x/002",\n'
           '    "/billing/invoices/download/03",\n'
           ']\n'
           'def has(route):\n'
           '    return route in ROUTE_PERMS\n'
           'H = has("/audit/logs/export/x/002")\n')
    tree, stats = transform(ast.parse(src), "app/main.py",
                            string_key=_KEY, module_id="main.py")
    assert stats["strings"] == 3                  # 唯一串数：实参与列表元素同串复用同条目
    dump = ast.dump(tree)
    for p in perms:
        assert p not in dump                      # 密文化：明文零残留
    ns = {}
    exec(compile(tree, "app/main.py", "exec"), ns)
    assert ns["ROUTE_PERMS"] == perms             # 运行期解密回原列表
    assert ns["H"] is True


def test_strings_forbidden_set_protection():
    """★M1★ 禁换集：同串在豁免位（装饰器实参/默认参）与替换位（Assign/
    Return）共存 → 替换位跳过不换（fate 一致，根除比较失败/查找断裂）。"""
    shared = "shared-long-value-000001"
    src = ('TAG = "shared-long-value-000001"\n'          # 替换位①：命中禁换集 → 跳过
           'def deco(s):\n'
           '    def w(fn):\n'
           '        fn.tag = s\n'
           '        return fn\n'
           '    return w\n'
           '@deco("shared-long-value-000001")\n'         # 豁免位①：装饰器实参
           'def f(x="shared-long-value-000001"):\n'      # 豁免位②：默认参
           '    return x == "shared-long-value-000001"\n'  # 替换位②：跳过
           'R = f()\n')
    tree, stats = transform(ast.parse(src), "app/main.py",
                            string_key=_KEY, module_id="main.py")
    assert stats["strings"] == 0                  # 唯一串全被禁换集保护
    assert shared in ast.dump(tree)               # 替换位保持明文（fate 一致）
    assert "_pkobf_d" not in ast.dump(tree)       # 零替换不注入 stub
    ns = {}
    exec(compile(tree, "app/main.py", "exec"), ns)
    assert ns["TAG"] == shared
    assert ns["R"] is True                        # 默认参与比较位同串同 fate


def test_strings_counter_reuse():
    """★M1★ counter 复用：同串两处 → 密文条目唯一（表长 = 唯一串数），两处
    同 idx，运行期解出同值；G5 首现序确定性不受影响。"""
    src = ('A = "reuse-same-long-string-01"\n'
           'B = "reuse-same-long-string-01"\n'
           'C = "other-distinct-long-str2"\n')
    tree, stats = transform(ast.parse(src), "app/main.py",
                            string_key=_KEY, module_id="main.py")
    assert stats["strings"] == 2                  # 表长 = 唯一串数（非出现次数）
    dump = ast.dump(tree)
    assert "reuse-same-long-string-01" not in dump
    calls = [n.args[0].value for n in ast.walk(tree)   # stub 取用点的 idx 分布
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
             and n.func.id == "_pkobf_d"]
    assert calls.count(0) == 2 and calls.count(1) == 1   # 同串两处同 idx=0
    ns = {}
    exec(compile(tree, "app/main.py", "exec"), ns)
    assert ns["A"] == ns["B"] == "reuse-same-long-string-01"
    assert len(ns["_TBL"]) == 2                   # 密文条目唯一
    assert ns["_TBL"][0] == "reuse-same-long-string-01"   # 首次取用即解密回写


# ---------------------------------------------------------------- M1-FB 修复回归
def test_strings_retained_docstring_forbidden():
    """★M1-FB-1★ 保留 docstring（class docstring 剥离豁免）吸收进禁换集：
    同串双位（docstring + 值位赋值）→ 值位不换、表长不含该串、
    ``C.__doc__ is V`` 身份一致（fate 分化即 False）。"""
    shared = "class-doc-shared-long-value"
    src = ('V = "class-doc-shared-long-value"\n'
           'class C:\n'
           '    """class-doc-shared-long-value"""\n')
    tree, stats = transform(ast.parse(src), "app/main.py",
                            string_key=_KEY, module_id="main.py")
    assert stats["strings"] == 0                  # 唯一串被禁换集保护，零条目
    assert "_pkobf_d" not in ast.dump(tree)       # 零替换不注入 stub
    ns = {}
    exec(compile(tree, "app/main.py", "exec"), ns)
    assert ns["C"].__doc__ == shared
    assert ns["C"].__doc__ is ns["V"]             # 同串同 fate：身份一致


def test_strings_type_params_bound_forbidden():
    """★M1-FB-2★ PEP 695 泛型形参 bound 吸收进禁换集：同串双位
    （bound + 值位）→ 值位不换、bound 保持明文，``__bound__ is V`` 身份一致。"""
    shared = "type-bound-shared-long-value"
    src = ('V = "type-bound-shared-long-value"\n'
           'def f[T: "type-bound-shared-long-value"](x):\n'
           '    return x\n')
    tree, stats = transform(ast.parse(src), "app/main.py",
                            string_key=_KEY, module_id="main.py")
    assert stats["strings"] == 0                  # 唯一串被禁换集保护，零条目
    assert "_pkobf_d" not in ast.dump(tree)
    assert shared in ast.dump(tree)               # bound 位保持明文
    ns = {}
    exec(compile(tree, "app/main.py", "exec"), ns)
    assert ns["f"](3) == 3
    assert ns["f"].__type_params__[0].__bound__ is ns["V"]   # 同串同 fate


def test_pure_docstring_body_no_crash():
    """★Issue 3★ 纯 docstring 函数/类：剥离后空体补 Pass → compile 不炸
    （原实现 ValueError: empty body）、exec 行为等价（cb() 可调用、C 可实例化、
    class docstring 保留）。"""
    src = ('def cb():\n'
           '    """callback-stub-only-docstring"""\n'
           'class C:\n'
           '    """class-with-only-docstring"""\n')
    ns1 = {}
    exec(compile(src, "t.py", "exec"), ns1)
    assert ns1["cb"]() is None
    assert isinstance(ns1["C"](), ns1["C"])
    code, stats = compile_obfuscated(src, "app/main.py")
    ns2 = {}
    exec(code, ns2)
    assert ns2["cb"]() is None                    # 剥离 docstring 后 Pass 兜底
    assert isinstance(ns2["C"](), ns2["C"])
    assert ns2["C"].__doc__ == "class-with-only-docstring"   # class docstring 保留
    assert stats["stripped"] == 1                 # 仅函数 docstring 被剥离


def test_strings_g5_deterministic():
    """G5：同 key 同 module_id 双跑 compile_obfuscated → pyc 组装字节一致；
    换 key → pyc 必变。注意：两次 compile 之间不得 exec——exec 会改变解释器
    intern/memo 历史，进程内 marshal 字节即漂移（生产子进程每跑新进程免疫）。"""
    from importlib._bootstrap_external import _code_to_hash_pyc
    from importlib.util import source_hash

    src = 'V = "deterministic-long-string-001"\n'
    runs = [compile_obfuscated(src, "app/main.py", string_key=_KEY,
                               module_id="main.py") for _ in range(2)]
    assert runs[0][1] == runs[1][1]              # G5 全字典一致（含 ledger/str_table）
    assert runs[0][1]["renamed"] == 0
    assert runs[0][1]["stripped"] == 0 and runs[0][1]["strings"] == 1
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
    # RFT 两遍后模块级 def 也进改名面：get→_o0 / gbk_fn→_o1 + 局部 x/y → 共 4；
    # 走通即解码正确（BOM / gbk 源码不炸）
    assert st["renamed"] == 4 and st["strings"] == 0


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


# ---------------------------------------------------------------- 期3 RFT（跨模块统一改名）
def _sym(mods, plan, mid, name):
    """取改名后的模块属性（plan.map 命中查新名，豁免/未知查原名）。"""
    return getattr(mods[mid], plan.map.get((mid, name), name))


def _exec_tree(codes):
    """{rel: code} → 接线 exec：祖先空壳补齐 → 父属性 setattr → 包先/按 mid 深度序
    exec 填充（import 语句在 exec 期查 sys.modules 命中，不走真 finder）。"""
    import sys
    mids = {rel: _module_id_for(rel) for rel in codes}
    created = []
    try:
        for mid in mids.values():
            for i in range(1, mid.count(".") + 2):
                anc = ".".join(mid.split(".")[:i])
                if anc not in sys.modules:
                    am = types.ModuleType(anc)
                    am.__path__ = []
                    am.__package__ = anc
                    sys.modules[anc] = am
                    created.append(anc)
        for rel, mid in mids.items():
            if "." in mid:
                pn, leaf = mid.rsplit(".", 1)
                setattr(sys.modules[pn], leaf, sys.modules[mid])
        order = sorted(codes, key=lambda r: (
            not r.endswith("__init__.py"), mids[r].count("."), r))
        mods = {}
        pending = order
        while pending:                       # from-import 依赖序：ImportError 延后重试
            rest = []
            for rel in pending:
                try:
                    exec(codes[rel], sys.modules[mids[rel]].__dict__)
                    mods[mids[rel]] = sys.modules[mids[rel]]
                except ImportError:
                    rest.append(rel)
            if len(rest) == len(pending):
                raise ImportError(f"exec 接线依赖不可满足: {rest}")
            pending = rest
        return mods
    finally:
        for mid in created:
            sys.modules.pop(mid, None)


def _xmod(sources, **kw):
    """RFT 多模块基建：plan → 原码/混淆码同构接线 exec，返回 (plan, 原mods, 混mods)。"""
    plan = build_rename_plan(sources, **kw)
    plain = {rel: compile(src, rel, "exec") for rel, src in sources.items()}
    obf = {rel: compile_obfuscated(src, rel, plan=plan)[0]
           for rel, src in sources.items()}
    return plan, _exec_tree(plain), _exec_tree(obf)


def test_xmod_basic_attr_chain_and_from_import():           # ① 跨模块映射基础
    sources = {
        "pkg/__init__.py": "def helper(x):\n    val = x + 1\n    return val\n\nCOUNT = 10\n",
        "main.py": "import app.pkg as p\nfrom app.pkg import COUNT\n\n"
                   "def use(v):\n    return p.helper(v) + COUNT\n",
    }
    plan, plain, obf = _xmod(sources)
    assert plan.map[("app.main", "use")] == "_o0"           # rels UTF-8 序 main 先分配
    assert plan.map[("app.pkg", "helper")] == "_o1"
    assert plan.map[("app.pkg", "COUNT")] == "_o2"
    assert plan.import_roots["app.main"]["p"] == "app.pkg"
    assert plain["app.main"].use(1) == 12
    assert _sym(obf, plan, "app.main", "use")(1) == 12      # 链改写 + from-import 回填


def test_xmod_relative_import_sync():                       # ② 相对 import 同步
    sources = {
        "pkg/__init__.py": "from .mod import helper\n\ndef call(v):\n    return helper(v)\n",
        "pkg/mod.py": "def helper(x):\n    return x * 2\n",
    }
    plan, plain, obf = _xmod(sources)
    assert plan.map[("app.pkg", "call")] == "_o0"           # init 先于 mod（rels 序）
    assert plan.map[("app.pkg.mod", "helper")] == "_o1"
    assert plan.from_rewrite["app.pkg"][(1, "mod", "helper")] == "_o1"
    assert plain["app.pkg"].call(5) == _sym(obf, plan, "app.pkg", "call")(5) == 10


def test_xmod_deep_attr_chain():                            # ③ 属性链 app.pkg.m2.helper
    sources = {
        "main.py": "import app.pkg.m2 as m\n\ndef go(v):\n    return m.helper(v)\n",
        "pkg/__init__.py": "KEEP = 1\n",
        "pkg/m2.py": "def helper(x):\n    return x + 3\n",
    }
    plan, plain, obf = _xmod(sources)
    assert plan.import_roots["app.main"]["m"] == "app.pkg.m2"
    assert plain["app.main"].go(1) == _sym(obf, plan, "app.main", "go")(1) == 4


def test_xmod_str_hit_exempt():                             # ④ 动态串豁免
    sources = {
        "pkg/__init__.py": "def helper(x):\n    return x\n",
        "main.py": "import app.pkg as p\n\ndef go():\n    return getattr(p, 'helper')(7)\n",
    }
    plan, plain, obf = _xmod(sources)
    assert plan.exempt[("app.pkg", "helper")] == "str-hit"
    assert ("app.pkg", "helper") not in plan.map
    assert _sym(obf, plan, "app.main", "go")() \
        == plain["app.main"].go() == 7                      # getattr 走原名


def test_xmod_star_import_exempt():                         # ⑤ star 豁免
    sources = {
        "pkg/__init__.py": "def helper(x):\n    return x\n",
        "main.py": "from app.pkg import *\n\ndef go(v):\n    return helper(v)\n",
    }
    plan, plain, obf = _xmod(sources)
    assert plan.exempt[("app.pkg", "helper")] == "star-import-src"
    assert _sym(obf, plan, "app.main", "go")(9) \
        == plain["app.main"].go(9) == 9


def test_xmod_entry_protected_pair():                       # ⑥ entry 保护对
    src = "async def app(scope, receive, send):\n    return None\n\nFLAG = 1\n"
    plan = build_rename_plan({"main.py": src},
                             protected_pairs=frozenset({("app.main", "app")}))
    assert plan.exempt[("app.main", "app")] == "protected"
    assert ("app.main", "FLAG") in plan.map
    bare = build_rename_plan({"main.py": src})
    assert ("app.main", "app") in bare.map                  # 无保护对则照改


def test_xmod_param_shadow_site():                          # ⑦ 站点级参数遮蔽豁免
    sources = {
        "pkg/__init__.py": "def helper(x):\n    return x\n",
        "main.py": "import app.pkg as p\n\nR = p.helper\n\ndef go(p):\n    return p.helper\n",
    }
    plan, plain, obf = _xmod(sources)
    assert plan.import_roots["app.main"]["p"] == "app.pkg"   # 参数绑定非 Store，防线不删
    class Dummy:
        helper = 7
    assert _sym(obf, plan, "app.main", "go")(Dummy()) == 7   # 参数遮蔽位不改写
    assert getattr(obf["app.main"], plan.map.get(("app.main", "R"), "R"))(3) \
        == plain["app.main"].R(3) == 3                      # 模块级链照改


def test_xmod_plan_deterministic():                         # ⑧ G5 计划确定性
    sources = {
        "pkg/__init__.py": "def helper(x):\n    val = x + 1\n    return val\n\nCOUNT = 10\n",
        "main.py": "import app.pkg as p\n\ndef use(v):\n    return p.helper(v)\n",
    }
    p1, p2 = build_rename_plan(sources), build_rename_plan(sources)
    for f in ("map", "exempt", "modset", "import_roots", "from_rewrite",
              "self_map", "stats"):
        assert getattr(p1, f) == getattr(p2, f), f
    assert p1.next_index == p2.next_index
    c1 = compile_obfuscated(sources["main.py"], "main.py", plan=p1)[0]
    c2 = compile_obfuscated(sources["main.py"], "main.py", plan=p2)[0]
    assert marshal.dumps(c1) == marshal.dumps(c2)


def test_xmod_counter_continuation():                       # ⑨ 全局计数器续位
    sources = {
        "pkg/__init__.py": "def helper(x):\n    y = x + 1\n    return y\n",
        "main.py": "import app.pkg as p\n\ndef use(v):\n    w = v * 2\n    return p.helper(w)\n",
    }
    plan = build_rename_plan(sources)
    assert plan.next_index == 2                     # main.use→_o0, pkg.helper→_o1（rels UTF-8 序）
    codes = {rel: compile_obfuscated(src, rel, plan=plan)[0]
             for rel, src in sources.items()}
    use_code = [c for c in _funcs(codes["main.py"]) if c.co_name == "_o0"][0]
    assert use_code.co_varnames == ("v", "_o2")     # 参数红线保留；局部 w 从 next_index 续位
    helper_code = [c for c in _funcs(codes["pkg/__init__.py"])
                   if c.co_name == "_o1"][0]
    assert "_o2" in helper_code.co_varnames                 # 各模块独立续位，不撞模块级


def test_xmod_cls_v1_exempt():                              # ⑩ 类名豁免（cls-v1）
    sources = {
        "pkg/__init__.py": "class Repo:\n    factor = 3\n\n    def get(self, v):\n"
                           "        return v * self.factor\n\n\ndef helper(x):\n"
                           "    return Repo().get(x)\n",
    }
    plan, plain, obf = _xmod(sources)
    assert plan.exempt[("app.pkg", "Repo")] == "cls-v1"
    assert ("app.pkg", "helper") in plan.map
    assert "Repo" in obf["app.pkg"].__dict__                # 类名保留
    assert _sym(obf, plan, "app.pkg", "helper")(5) == plain["app.pkg"].helper(5) == 15


def test_xmod_dunder_imported_escape():                     # ⑪ dunder/imported/escape
    sources = {
        "m.py": "import os\n__version__ = '1.0'\n"
                "def rec():\n    return rec\n\ndef plain(v):\n    return v + 1\n",
    }
    plan, plain, obf = _xmod(sources)
    assert ("app.m", "plain") in plan.map
    assert plan.exempt[("app.m", "rec")] == "escape"
    assert ("app.m", "__version__") not in plan.map         # dunder 红线
    assert ("app.m", "os") not in plan.map                  # import 绑定红线
    assert obf["app.m"].rec() is obf["app.m"].rec()         # 自引用语义保持
    assert _sym(obf, plan, "app.m", "plain")(1) == 2


def test_xmod_submodule_conflict():                         # ⑫ 子模块名冲突豁免
    sources = {
        "pkg/__init__.py": "def m2(x):\n    return x + 1\n\nuse_sub = 0\n",
        "pkg/m2.py": "def inner(x):\n    return x * 2\n",
        "main.py": "from app.pkg.m2 import inner\n\ndef go(v):\n    return inner(v)\n",
    }
    plan, plain, obf = _xmod(sources)
    assert plan.exempt[("app.pkg", "m2")] == "submodule-shadow"
    assert plan.map[("app.pkg.m2", "inner")] == "_o2"       # go→_o0, use_sub→_o1
    assert plain["app.main"].go(3) == _sym(obf, plan, "app.main", "go")(3) == 6


def test_module_id_parity_with_keylib():                    # 子进程裸导入对拍锁
    from pkapp.packager.keylib import module_id_for
    for rel in ("main.py", "__init__.py", "pkg/__init__.py", "pkg/mod.py",
                "a/b/c.py", "a/b/__init__.py", "deep/nest/leaf/__init__.py"):
        assert _module_id_for(rel) == module_id_for(rel), rel


# ---------------------------------------------------------------- ★R-13★ 双编译对拍（§4.1.5 ①）
from pkapp.packager.obfuscate import ParityError, verify_parity

_KEY = bytes(range(32))


def test_parity_single_module_composite():
    """复合变换正例：改名 + docstring 剥离 + 字符串加密（长串换/短串留/f-string/
    保留 doctest）全场景对拍通过——两表逐项解释全部符号面差异。"""
    src = ('"""mod doc."""\n'
           'WIDE = "a-long-enough-secret-string!"\n'
           'SHORT = "short"\n'
           'def go(x):\n'
           '    """fn doc."""\n'
           '    tag = "another-long-secret-value"\n'
           '    return WIDE[:4] + f"{x}-{SHORT}" + tag[:3]\n'
           'class Keep:\n'
           '    """class doc retained."""\n'
           '    def m(self):\n'
           '        return "yet-one-more-long-string"\n')
    code, stats = compile_obfuscated(src, "m.py", string_key=_KEY, module_id="app.m")
    verify_parity(src, "m.py", code, stats, string_key=_KEY, module_id="app.m")


def test_parity_plan_cross_module():
    """RFT plan 复合正例：跨模块 attr 链 + from-import 改写 + 模块级/局部改名，
    每模块对拍通过（台账 = plan.map 模块级 + 局部 + 属性链 + from-import）。"""
    sources = {
        "pkg/__init__.py": 'COUNT = 10\n\ndef helper(x):\n    val = x + 1\n    return val\n',
        "main.py": 'import app.pkg as p\nfrom app.pkg import COUNT\n\n'
                   'def use(v):\n    return p.helper(v) + COUNT\n',
    }
    plan = build_rename_plan(sources)
    for rel, src in sources.items():
        code, stats = compile_obfuscated(src, rel, plan=plan)
        verify_parity(src, rel, code, stats)


def test_parity_no_string_pass():
    """仅改名（无 string_key）对拍通过：台账解释全部差异，无密钥表介入。
    一期模式模块级名不改（go 保留），只有函数局部 w 进台账。"""
    src = 'def go(v):\n    w = v * 2\n    return w + 1\n'
    code, stats = compile_obfuscated(src, "m.py")
    assert stats["ledger"] == frozenset({("w", "_o0")})
    verify_parity(src, "m.py", code, stats)


def test_parity_detects_wrong_key():
    """验牙①：密钥表换钥 → 密文重算不匹配 → 新现 bytes 无解释 → ParityError。"""
    src = 'V = "a-long-enough-secret-string!"\n'
    code, stats = compile_obfuscated(src, "m.py", string_key=_KEY, module_id="app.m")
    with pytest.raises(ParityError, match="新现常量"):
        verify_parity(src, "m.py", code, stats,
                      string_key=bytes(range(32, 64)), module_id="app.m")


def test_parity_detects_source_drift():
    """验牙②：对拍参照源与产物源漂移（多一个函数）→ 子 code 数不匹配 → 炸。"""
    src = 'def go(v):\n    return v + 1\n'
    drifted = src + '\ndef extra():\n    return 1\n'
    code, stats = compile_obfuscated(drifted, "m.py")
    with pytest.raises(ParityError, match="子 code object"):
        verify_parity(src, "m.py", code, stats)


def test_parity_detects_name_out_of_ledger():
    """验牙③：台账被抽走一条 → 对应消失名无解释 → 炸（全量断言非抽样）。"""
    src = 'def go(v):\n    w = v * 2\n    return w\n'
    code, stats = compile_obfuscated(src, "m.py")
    stats["ledger"] = frozenset(x for x in stats["ledger"] if x[0] != "w")
    with pytest.raises(ParityError, match="消失名"):
        verify_parity(src, "m.py", code, stats)


def test_parity_constkey_map_degraded():
    """★P1.5★ 伴生对拍规则：全常量键 dict 编译为 BUILD_CONST_KEY_MAP（键 =
    str 元组常量）；任一键 ≥_MIN_STR(8) 被加密替换为 _pkobf_d(idx) Call 后
    3.12 编译器退化 BUILD_MAP——键元组消失、未加密键散为独立常量。
    keymap_degraded 规则：逐元素 ∈ (str_table ∪ 新现散串) 全命中放行。"""
    src = ('def go(v):\n'
           '    return {"hello": "world", "data_dir": v, "cfg_file": 1}\n')
    code, stats = compile_obfuscated(src, "m.py", string_key=_KEY,
                                     module_id="app.m")
    verify_parity(src, "m.py", code, stats, string_key=_KEY, module_id="app.m")


def test_parity_constkey_map_degraded_negative():
    """验牙④：键元组退化规则不放走真漂移——密钥表抽走加密键条目 → 该元素
    既不在表也未散现 → 消失常量报错（部分命中必拒，全量断言非抽样）。"""
    src = 'def go(v):\n    return {"hello": "world", "data_dir": v}\n'
    code, stats = compile_obfuscated(src, "m.py", string_key=_KEY,
                                     module_id="app.m")
    stats["str_table"] = [s for s in stats["str_table"] if s != "data_dir"]
    with pytest.raises(ParityError, match="消失常量"):
        verify_parity(src, "m.py", code, stats, string_key=_KEY,
                      module_id="app.m")


def test_parity_docstring_none_slot():
    """docstring 剥离伴生（真实项目 db.py 抓出）：3.12 函数 scope const 池恒带
    docstring 槽位，无 docstring 时填 None 占位——原码「docstring + 全函数无
    None」的函数剥离后 consts[0] 从 docstring 变 None，出现「消失 str(consts[0])
    + 新现 None」成对差异，规则须成对解释（原码本有 None 的函数去重无 diff，
    如 x[:4] 的 BINARY_SLICE start=None）。"""
    src = ('def now() -> str:\n'
           '    """ISO 秒级时间戳（共用）。"""\n'
           '    return datetime.now().isoformat(timespec="seconds")\n')
    code, stats = compile_obfuscated(src, "db.py", string_key=_KEY,
                                     module_id="db.py")
    verify_parity(src, "db.py", code, stats, string_key=_KEY, module_id="db.py")


def test_parity_const_fold_degraded():
    """折叠体退化伴生（真实项目 main.py/roles.py 抓出）：全常量容器字面量
    （list-of-tuples / set）被 3.12 整体折叠为嵌套元组/frozenset 常量；任一
    str 叶子被加密后折叠失效摊平——未加密叶子散现（子元组或散串）、加密叶子
    进密钥表，逐叶子全命中放行。"""
    src = ('ROUTE = [("GET", "/api/me"), ("POST", "/api/devices-list")]\n'
           'ROLES = {"r": {"device.read", "event.read"}}\n')
    plan = build_rename_plan({"m.py": src})
    code, stats = compile_obfuscated(src, "m.py", string_key=_KEY,
                                     module_id="m.py", plan=plan)
    verify_parity(src, "m.py", code, stats, string_key=_KEY, module_id="m.py")


def test_parity_annotation_drift():
    """注解 const 漂移伴生（真实项目 schemas.py/roles.py 抓出）：3.12 类体
    注解字符串化 / AnnAssign 的 __annotations__ 键——注解文本内的名字 = AST
    Name，RFT 改名后编译器重生成注解字符串（'DeviceStatus | None' →
    '_o53 | None'、键 'ROLES' → '_o21'）。台账全词替换逐字相等放行；
    运行期解析走模块命名空间，引用与绑定同步漂移，语义等价。"""
    src = ('from typing import Literal\n'
           'DeviceStatus = Literal["online", "error"]\n'
           'class DeviceCreate:\n'
           '    status: DeviceStatus = "online"\n'
           'ROLES: dict = {"admin": "*"}\n')
    plan = build_rename_plan({"m.py": src})
    code, stats = compile_obfuscated(src, "m.py", plan=plan)
    verify_parity(src, "m.py", code, stats)
    led = dict(stats["ledger"])
    assert "_o0" in led.values() or len(led) >= 1      # 类名豁免，变量/注解键漂移进台账


def test_parity_no_docstring_first_const_not_exempted():
    """★评审修复②★ 无 docstring 时 scope consts[0] 是首个业务常量，其消失
    不得凭位次豁免（旧判定 `c == a[0]` 会把短串真实漂移误放）。人为剔除模块
    首常量构造漂移，ParityError 必须炸；对照：真 docstring 的位次豁免仍由
    test_parity_docstring_none_slot 正例覆盖。"""
    src = ('X = "ab"\n'          # <8 短串：不开加密时不进密钥表，无任何合法消失路径
           'def f():\n'
           '    return X\n')
    code, stats = compile_obfuscated(src, "m.py")
    verify_parity(src, "m.py", code, stats)            # 完整 code 对拍通过
    drifted = code.replace(co_consts=tuple(c for c in code.co_consts if c != "ab"))
    with pytest.raises(ParityError, match="消失常量"):
        verify_parity(src, "m.py", drifted, stats)     # 人为漂移 → 当场炸


def test_parity_annotation_drift_single_pass():
    """★评审修复③★ 台账单趟交替替换：v1 与 Wv1（orig 词互为前缀包含）同入
    台账——交替 pattern 共享 \\b 边界必须靠回溯保证最长词形唯一命中（v1 先试
    匹配 Wv1 时尾 \\b 失败），替换后对拍仍逐字精确；同时锁「单趟无链式污染」
    的实现合同（跨 scope orig 名与新名撞形 _oK 时，链式 re.sub 的结果依赖
    frozenset 迭代序，单趟替换与序无关）。"""
    src = ('v1 = 1\n'
           'Wv1 = 2\n'
           'class C:\n'
           '    x: Wv1 = 0\n')
    plan = build_rename_plan({"m.py": src})
    code, stats = compile_obfuscated(src, "m.py", plan=plan)
    verify_parity(src, "m.py", code, stats)
