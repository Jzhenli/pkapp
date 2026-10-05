"""构建期混淆层一期（★§13 混淆叠加层★）：symtable 驱动的安全符号改名 + docstring 剥离。

定稿设计（S1，纯 stdlib：ast/symtable/types）：

- 改名面：仅 function scope 的非参数局部绑定——``is_local()`` 且非 parameter、
  非 global、非 import 绑定、非 dunder、不在 protected。新名 ``_o{n}`` 单文件
  全局计数器按首现序分配（作用域树 DFS = 建块序；名字按 get_symbols() 返回序）。
- 白名单合同（逐项不改）：函数参数（FastAPI 查询参数名派生自参数名、关键字实参
  公开）、类体内名（pydantic 字段 / self.x 属性访问合同）、global 声明名、
  import 绑定名、模块级名（含 _x 私有）、调用侧 keyword.arg。
- AST 单遍 NodeTransformer + scope 栈跟随：
  * Name 三种 ctx（Store/Load/Del）统一查映射——漏改 Del 会 NameError；
  * 查找沿父链只穿越 function scope：任一中间 function scope 映射命中即用；
    遇本层绑定（参数遮蔽 / global 声明）即止，绝不穿透改名（否则语义漂移）；
  * FunctionDef.name：仅当父 scope 是 function 且名字在父 scope 候选集内才改；
    逃逸豁免——函数体存在直接 ``return <自身名>`` / ``yield <自身名>``（递归/
    生成器委托自引用）→ 该名整体不改（★OB-1★ 豁免判定前移：改名前整树预扫描
    收集豁免名，阶段一候选分配时即排除出映射——visit 到 def 时才 del 会让先前
    已按映射改写的引用悬空：前向引用兄弟 NameError / 同名重定义 split-binding）；
  * except-as：ExceptHandler.name 与体内 Name 同映射（块尾隐式 del 无 AST 节点，
    两端一致即安全）；match 捕获名（MatchAs/MatchStar/MatchMapping.rest）同理；
  * walrus target 同 Name 规则；Attribute.attr / keyword.arg 是字符串字段，天然不碰。
- docstring 剥离：模块与无装饰器函数的 body[0] 字符串常量删；带装饰器（FastAPI
  路由 OpenAPI description）、含 >>>（doctest）、class（pydantic description 派生）
  豁免。Expr(Constant) 删除不重排行号——compile(ast_obj) 保留其余语句 lineno。
- P709 坑位：3.12 list/set/dict 推导式已内联（无独立 symtable 子 scope，目标变量
  是外层 function 的 local，正常走映射）；genexpr 仍是独立 function scope（外层名
  is_free，父链查找覆盖；首迭代器在外层求值——入栈前访问）。3.12 泛型（type
  parameter 包装块）：类型形参名入 shield 排除出候选，且包装块认领时向内穿透一层。

期2（§13.3③ S5/S6）：确定性 keystream + 保守字符串加密 pass。
- keystream：SHA256(key32 ‖ module_id ‖ counter_u32_be) 逐块（32B）拼接截断，
  counter 从 0 大端——同 (key32, module_id) → 同流（G5 确定性的唯一依据）。
- 字符串 pass 在改名 pass 之后跑（scope 结构稳定；注入名天然不参与改名）：
  直值位（Expr 语句 / Assign value / Return value / Compare 比较元）的 ≥16 长串
  替换为 _pkobf_d(idx)，密文表 _TBL 与惰性解密 stub 注入模块头（docstring 与
  __future__ import 之后）；替换点收集序 = 表序（确定）。stub 源码由本文件
  keystream/xor_bytes 同一 Python 语义源码化生成（避免双端漂移），key32 以 XOR
  包裹态 + mask（keystream(key32, module_id+":stubmask", 32) 自裹派生）双常量
  分持内嵌——key32 字面量不出现，运行期 stub 先恢复 key32 再对流解密。
- 豁免面（从严，各配测试）：装饰器参数、函数默认参数、注解（AnnAssign/arg/
  returns）、match case pattern、__all__ 赋值、JoinedStr（f-string）整体、
  bytes、短串（<16）、模块/函数/类 docstring 位置；业务源码占用 _TBL/_pkobf_d
  名 → ValueError 拒绝（极端保守）。
"""
from __future__ import annotations

import ast
import hashlib
import symtable
import types

__all__ = ["transform", "compile_obfuscated", "keystream", "xor_bytes"]

# 兼容不同打包解释器版本的作用域块名（3.12 推导式内联无块；3.10/3.11 回退编译带块）
_LAMBDA_NAMES = ("lambda", "<lambda>")
_GENEXPR_NAMES = ("genexpr", "<genexpr>")
_LISTCOMP_NAMES = ("listcomp", "<listcomp>")
_SETCOMP_NAMES = ("setcomp", "<setcomp>")
_DICTCOMP_NAMES = ("dictcomp", "<dictcomp>")

# ---------------------------------------------------------------- keystream 层（§13.3③ S5）
_MIN_STR = 16                      # 字符串加密最小长度（≥16 才替换）
_STUB_TABLE = "_TBL"               # 密文表（模块级注入名）
_STUB_FUNC = "_pkobf_d"            # 惰性解密 stub（模块级注入名）
_STUB_NAMES = frozenset((_STUB_TABLE, _STUB_FUNC))
_MASK_TAG = ":stubmask"            # key32 自裹 mask 的 module_id 派生后缀


def keystream(key32: bytes, module_id: str, length: int) -> bytes:
    """确定性 keystream（★§13.3③ S5★，G5 双端一致的唯一依据）：
    SHA256(key32 ‖ module_id ‖ counter_u32_be) 逐块（32B/块）拼接后截断到
    length，counter 从 0 起大端。同 (key32, module_id) → 同流；改任一 → 流变。
    """
    if length <= 0:
        return b""
    mid = module_id.encode("utf-8")
    out = bytearray()
    counter = 0
    while len(out) < length:
        out.extend(hashlib.sha256(key32 + mid + counter.to_bytes(4, "big")).digest())
        counter += 1
    return bytes(out[:length])


def xor_bytes(data: bytes, stream: bytes) -> bytes:
    """等长 XOR（zip 截断语义 = keystream 截断语义，stub 内联版同款）。"""
    return bytes(a ^ b for a, b in zip(data, stream))


class _Scope:
    """symtable 块 ↔ 父链 ↔ 改名映射（仅 function scope 建映射）。"""

    __slots__ = ("block", "parent", "kind", "name", "symbols", "mapping",
                 "children", "consumed")

    def __init__(self, block: symtable.SymbolTable, parent: "_Scope | None"):
        self.block = block
        self.parent = parent
        self.kind = block.get_type()
        self.name = block.get_name()
        self.symbols = {s.get_name(): s for s in block.get_symbols()}
        self.mapping: dict[str, str] = {}
        self.children: list[_Scope] = []
        self.consumed = False


def _build_scopes(block: symtable.SymbolTable, parent: _Scope | None,
                  protected: frozenset[str], counter: list[int],
                  out: list[_Scope],
                  escape_names: frozenset[str] = frozenset()) -> _Scope:
    """阶段一：纯 symtable 块树建作用域树 + 逐 scope 收集改名候选（确定序）。

    escape_names = 逃逸豁免名集（★OB-1★ 预扫描产物，必须在候选分配**之前**
    就绪）：命中的名字根本不进映射（不是分配后删——分配后 del 会让先前已按
    映射改写的引用悬空）。按名字全局排除是保守上界：跨 scope 同名的非豁免
    绑定连带保持原名——原名恒语义正确，仅损失改名覆盖率；ast.walk 无 scope
    归属信息，精确 (scope, name) 归属需 AST↔symtable 块关联，成本不成比例。
    """
    scope = _Scope(block, parent)
    out.append(scope)
    if scope.kind == "function":
        # 3.12 泛型 shield：祖先 type parameter 包装块绑定的类型形参名不可改
        # （TypeVar 节点的 name 是字符串字段，改 annotation 而不改形参 = 两端断裂）
        shield: set[str] = set()
        s = parent
        while s is not None:
            if s.kind not in ("function", "class", "module"):
                shield.update(nm for nm, sym in s.symbols.items() if sym.is_local())
            s = s.parent
        for sym in block.get_symbols():          # get_symbols() 返回序 = 确定序
            n = sym.get_name()
            if (sym.is_local() and not sym.is_parameter() and not sym.is_global()
                    and not sym.is_imported()
                    and not (n.startswith("__") and n.endswith("__"))
                    and n not in protected and n not in shield
                    and n not in escape_names):
                scope.mapping[n] = "_o%d" % counter[0]
                counter[0] += 1
    for child in block.get_children():           # 建块序 = ast 遍历序（确定）
        scope.children.append(
            _build_scopes(child, scope, protected, counter, out, escape_names))
    return scope


def _escape_exempt(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """逃逸豁免扫描：函数体（不深入嵌套作用域）存在直接 return/yield 自身名。"""
    name = node.name
    stack: list[ast.AST] = list(node.body)
    while stack:
        nd = stack.pop()
        if isinstance(nd, (ast.FunctionDef, ast.AsyncFunctionDef,
                           ast.Lambda, ast.ClassDef)):
            continue                              # 嵌套作用域内的自引用不算直接逃逸
        if isinstance(nd, ast.Return):
            v = nd.value
            if isinstance(v, ast.Name) and v.id == name:
                return True
        elif isinstance(nd, ast.Yield):
            v = nd.value
            if isinstance(v, ast.Name) and v.id == name:
                return True
        stack.extend(ast.iter_child_nodes(nd))
    return False


def _escape_exempt_names(tree: ast.Module) -> frozenset[str]:
    """★OB-1★ 逃逸豁免预扫描：整树收集命中豁免条件的函数名（ast.walk 即可）。

    判定标准与 _escape_exempt 完全一致，只移时序——必须在阶段一候选分配之前
    完成，保证引用改写时映射终态已定。按名字全局排除（保守上界，理由见
    _build_scopes docstring）。"""
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                and _escape_exempt(node):
            out.add(node.name)
    return frozenset(out)


class _Renamer(ast.NodeTransformer):
    """阶段二：单遍 AST 改写，scope 栈跟随 AST 结构与块树认领式对齐。"""

    def __init__(self, root: _Scope):
        self._stack = [root]
        self.stripped = 0

    # ---- 作用域对齐 ----
    @property
    def _cur(self) -> _Scope:
        return self._stack[-1]

    def _claim(self, name: str, kinds: tuple[str, ...]) -> _Scope | None:
        """在当前 scope 的未消费子块中按 (名, 类型) 认领——同名兄弟按序消费，
        与 symtable 建块序一致；3.12 泛型的 type parameter 包装块向内穿透一层。"""
        for sc in self._cur.children:
            if not sc.consumed and sc.kind in kinds and sc.name == name:
                sc.consumed = True
                return sc
        for sc in self._cur.children:
            if (sc.consumed or sc.kind in ("function", "class", "module")
                    or sc.name != name):
                continue
            for gc in sc.children:
                if not gc.consumed and gc.kind in kinds and gc.name == name:
                    gc.consumed = True
                    return gc
        return None

    def _lookup(self, name: str) -> str | None:
        """名字查找：沿父链只穿越 function scope，映射命中即改，遇本层绑定即止。"""
        s: _Scope | None = self._stack[-1]
        while s is not None:
            if s.kind == "function":
                new = s.mapping.get(name)
                if new is not None:
                    return new
                sym = s.symbols.get(name)
                if sym is not None and (sym.is_local() or sym.is_parameter()
                                        or sym.is_global()):
                    return None          # 本层绑定（含参数遮蔽）/ global → 止步不改
            elif s.kind == "class":
                sym = s.symbols.get(name)
                if sym is not None and sym.is_local():
                    return None          # 类体内名是合同（pydantic 字段等）
            elif s.kind == "module":
                return None              # 模块级名 / builtins 永不改
            else:
                sym = s.symbols.get(name)
                if sym is not None and sym.is_local():
                    return None          # type parameter 等包装块的绑定名（类型形参）
            s = s.parent
        return None

    # ---- docstring 剥离 ----
    def _strip_docstring(self, node) -> None:
        """body[0] 为字符串常量 Expr → 删除（含 >>> 的 doctest 豁免）；
        class docstring / 带装饰器函数由调用方豁免（不调用本方法）。"""
        if not node.body:
            return
        first = node.body[0]
        if (isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)
                and ">>>" not in first.value.value):
            node.body.pop(0)             # 只删节点不重排：其余语句 lineno 原样
            self.stripped += 1

    # ---- 函数名改名 ----
    def _rename_defname(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """函数名 = 父 scope 的 function-local binding 才改。

        ★OB-1★ 豁免名在阶段一已被排除出映射（映射终态前置到引用改写之前），
        此处不再判豁免、更不 del——visit 时才删映射会让先前已按映射改写的引用
        悬空（前向引用兄弟 / 同名重定义 split-binding）。"""
        parent = self._cur
        if parent.kind != "function" or node.name not in parent.mapping:
            return
        node.name = parent.mapping[node.name]

    def _visit_signature(self, args: ast.arguments) -> None:
        """默认值 / 参数注解在外层 scope 求值（Python 语义）——入栈前访问；
        arg.arg 永不改（参数名是公开合同）。"""
        params = [*args.posonlyargs, *args.args, *args.kwonlyargs]
        if args.vararg is not None:
            params.append(args.vararg)
        if args.kwarg is not None:
            params.append(args.kwarg)
        for a in params:
            if a.annotation is not None:
                a.annotation = self.visit(a.annotation)
        args.defaults = [self.visit(d) for d in args.defaults]
        args.kw_defaults = [self.visit(d) if d is not None else None
                            for d in args.kw_defaults]

    # ---- 语句级节点 ----
    def visit_Module(self, node: ast.Module) -> ast.Module:
        self._strip_docstring(node)          # 模块 docstring 剥
        node.body = [self.visit(s) for s in node.body]
        return node

    def _do_function(self, node):
        child = self._claim(node.name, ("function",))   # 先认领（块名是原名）
        self._rename_defname(node)
        node.decorator_list = [self.visit(d) for d in node.decorator_list]
        self._visit_signature(node.args)
        if node.returns is not None:
            node.returns = self.visit(node.returns)
        if getattr(node, "type_params", None):
            node.type_params = [self.visit(t) for t in node.type_params]
        if not node.decorator_list:          # 带装饰器豁免（FastAPI OpenAPI）
            self._strip_docstring(node)
        if child is not None:
            self._stack.append(child)
            try:
                node.body = [self.visit(s) for s in node.body]
            finally:
                self._stack.pop()
        else:                                # 兜底（块树意外缺块时保持可编译）
            node.body = [self.visit(s) for s in node.body]
        return node

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        return self._do_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        return self._do_function(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.ClassDef:
        # 类体内名不改（pydantic 字段 / self.x 合同）；类 scope 只提供父链。
        # 类名本身 = 父 scope 的 function-local binding → 与函数名同规则改
        # （symtable 里类绑定就是普通 local，只改引用不改 def 名会两端断裂）。
        child = self._claim(node.name, ("class",))
        self._rename_defname(node)
        node.decorator_list = [self.visit(d) for d in node.decorator_list]
        node.bases = [self.visit(b) for b in node.bases]
        for kw in node.keywords:
            kw.value = self.visit(kw.value)  # keyword.arg 字符串字段不碰
        if getattr(node, "type_params", None):
            node.type_params = [self.visit(t) for t in node.type_params]
        # class docstring 豁免（pydantic description 派生）
        if child is not None:
            self._stack.append(child)
            try:
                node.body = [self.visit(s) for s in node.body]
            finally:
                self._stack.pop()
        else:
            node.body = [self.visit(s) for s in node.body]
        return node

    def visit_Lambda(self, node: ast.Lambda) -> ast.Lambda:
        child = None
        for nm in _LAMBDA_NAMES:
            child = self._claim(nm, ("function",))
            if child is not None:
                break
        self._visit_signature(node.args)     # lambda 默认值在外层求值
        if child is not None:
            self._stack.append(child)
        try:
            node.body = self.visit(node.body)
        finally:
            if child is not None:
                self._stack.pop()
        return node

    # ---- 推导式（P709：3.12 list/set/dict 已内联无块；genexpr 仍是 function 块）----
    def _do_comprehension(self, node, names: tuple[str, ...]):
        node.generators[0].iter = self.visit(node.generators[0].iter)  # 首迭代器外层求值
        child = None
        for nm in names:
            child = self._claim(nm, ("function",))
            if child is not None:
                break
        if child is not None:
            self._stack.append(child)
        try:
            for i, gen in enumerate(node.generators):
                gen.target = self.visit(gen.target)
                if i:
                    gen.iter = self.visit(gen.iter)
                for cond in gen.ifs:
                    self.visit(cond)
            if isinstance(node, ast.DictComp):
                node.key = self.visit(node.key)
                node.value = self.visit(node.value)
            else:
                node.elt = self.visit(node.elt)
        finally:
            if child is not None:
                self._stack.pop()
        return node

    def visit_GeneratorExp(self, node: ast.GeneratorExp):
        return self._do_comprehension(node, _GENEXPR_NAMES)

    def visit_ListComp(self, node: ast.ListComp):
        return self._do_comprehension(node, _LISTCOMP_NAMES)

    def visit_SetComp(self, node: ast.SetComp):
        return self._do_comprehension(node, _SETCOMP_NAMES)

    def visit_DictComp(self, node: ast.DictComp):
        return self._do_comprehension(node, _DICTCOMP_NAMES)

    # ---- 表达式级节点 ----
    def visit_Name(self, node: ast.Name) -> ast.Name:
        new = self._lookup(node.id)
        if new is not None:
            node.id = new                    # ctx 无关：Store/Load/Del 统一（漏改 Del 会 NameError）
        return node

    def visit_Nonlocal(self, node: ast.Nonlocal) -> ast.Nonlocal:
        # nonlocal 语句名串须与定义 scope 的映射一致（漏改 = SyntaxError 断裂）
        node.names = [self._lookup(nm) or nm for nm in node.names]
        return node

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> ast.ExceptHandler:
        if node.type is not None:
            node.type = self.visit(node.type)
        if node.name:
            new = self._lookup(node.name)
            if new is not None:
                node.name = new              # 与体内 Name 同映射（隐式 del 两端一致）
        node.body = [self.visit(s) for s in node.body]
        return node

    def visit_MatchAs(self, node: ast.MatchAs) -> ast.MatchAs:
        if node.pattern is not None:
            node.pattern = self.visit(node.pattern)
        if node.name:
            new = self._lookup(node.name)
            if new is not None:
                node.name = new              # 捕获名与 case 体内 Name 同映射
        return node

    def visit_MatchStar(self, node: ast.MatchStar) -> ast.MatchStar:
        if node.name:
            new = self._lookup(node.name)
            if new is not None:
                node.name = new
        return node

    def visit_MatchMapping(self, node: ast.MatchMapping) -> ast.MatchMapping:
        node.keys = [self.visit(k) for k in node.keys]
        node.patterns = [self.visit(p) for p in node.patterns]
        if node.rest:
            new = self._lookup(node.rest)
            if new is not None:
                node.rest = new
        return node


def _is_docstring_stmt(stmt) -> bool:
    """docstring 位置判定：body[0] 的 Expr(Constant(str))（业务字符串豁免区）。"""
    return (isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant)
            and isinstance(stmt.value.value, str))


# stub 源码模板（★源码化注入★：stub = 构建期 keystream/xor_bytes 的等价内联版，
# 由本文件同一实现派生全部常量——避免双端漂移）。keystream 派生输入不明文内嵌：
# key32 以 XOR 包裹态（wrapped）与其 mask（keystream(key32, module_id+":stubmask",
# 32) 自裹派生）双常量分持——运行期 stub 先恢复 key32 再对流解密，key32 字面量
# 不出现；module_id 可作烘焙常量；stdlib-only（仅 import hashlib）。
_STUB_SRC = '''\
def {fn}(i):
    _b = {tbl}[i]
    if _b.__class__ is str:
        return _b                      # 惰性一次性：首次解密回写，二次命中缓存
    import hashlib as _h
    _k = bytes(_x ^ _y for _x, _y in zip({wrapped}, {mask}))
    _mid = {module_id}
    _st = bytearray()
    _c = 0
    while len(_st) < len(_b):
        _st += _h.sha256(_k + _mid.encode() + _c.to_bytes(4, 'big')).digest()
        _c += 1
    _p = bytes(_x ^ _y for _x, _y in zip(_b, _st)).decode('utf-8')
    {tbl}[i] = _p
    return _p
'''


def _stub_statements(table: list[bytes], key32: bytes, module_id: str) -> list[ast.stmt]:
    """生成 _TBL 赋值 + _pkobf_d def 的 AST 语句（parse 自源码模板；常量烘焙）。

    wrapped = key32 XOR keystream(key32, module_id+":stubmask", 32)（自裹派生，
    mask 与 wrapped 分持内嵌——恢复 key32 = wrapped ^ mask，key32 字面量不出现）。
    """
    mask = keystream(key32, module_id + _MASK_TAG, 32)
    wrapped = xor_bytes(key32, mask)
    tbl_src = "%s = [%s]" % (_STUB_TABLE, ", ".join(repr(b) for b in table))
    src = tbl_src + "\n" + _STUB_SRC.format(
        fn=_STUB_FUNC, tbl=_STUB_TABLE, wrapped=repr(wrapped),
        mask=repr(mask), module_id=repr(module_id))
    return ast.parse(src).body


def _check_stub_name_conflicts(tree: ast.Module) -> None:
    """极端保守：业务源码以任何标识符形态占用 _TBL/_pkobf_d → ValueError 拒绝
    （在改名 pass 之后检查——函数局部占用已被改名消化，只剩真冲突）。

    ★OB-3★ import alias 补漏：asname 优先（import a as _TBL 绑定 _TBL）；无
    asname 时首段/尾段任一命中即拒——`import a._TBL` 绑定名实为 a，误拒可
    接受（保守优先，改写成 asname 即绕过）；`from pkg import _TBL` 绑定
    _TBL 被尾段命中拒绝。"""
    for node in ast.walk(tree):
        hit = None
        if isinstance(node, ast.Name):
            hit = node.id
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            hit = node.name
        elif isinstance(node, ast.arg):
            hit = node.arg
        elif isinstance(node, ast.alias):
            if node.asname:
                hit = node.asname
            else:
                # 无 asname：首段/尾段任一命中即冲突（hit 存命中的段名——
                # 存整串会与 _STUB_NAMES 精确比对断裂，如 "a._TBL" != "_TBL"）
                parts = node.name.split(".")
                if parts[0] in _STUB_NAMES:
                    hit = parts[0]
                elif parts[-1] in _STUB_NAMES:
                    hit = parts[-1]
        if hit in _STUB_NAMES:
            raise ValueError(
                f"业务源码占用混淆 stub 名 {hit!r}，字符串加密拒绝执行")


class _StringCipher(ast.NodeTransformer):
    """字符串加密 pass（§13.3③ S6，在改名 pass 之后跑）。

    替换面（保守，仅四类直值位）：Expr 语句值 / Assign value / Return value /
    Compare 比较元（left 与 comparators），且 Constant(str) 且 len ≥ 16——
    容器内/嵌套表达式内的值上下文一律不处理（从严豁免）。
    明确不改（整子域不下降）：装饰器参数、函数默认参数与注解、AnnAssign 注解、
    match case pattern、__all__ 赋值、JoinedStr（f-string）、docstring 位置；
    bytes / 短串（<16）天然不命中。注入的 Call 里 Constant(idx) 是 int 不受影响。
    """

    def __init__(self, key32: bytes, module_id: str):
        self._key = key32
        self._mid = module_id
        self.table: list[bytes] = []   # 密文表（序 = 收集序 = 替换 idx 序，确定）

    # ---- 直值位替换 ----
    def _slot(self, v):
        if (isinstance(v, ast.Constant) and isinstance(v.value, str)
                and len(v.value) >= _MIN_STR):
            raw = v.value.encode("utf-8")
            idx = len(self.table)
            self.table.append(xor_bytes(raw, keystream(self._key, self._mid,
                                                       len(raw))))
            return ast.copy_location(
                ast.Call(func=ast.Name(id=_STUB_FUNC, ctx=ast.Load()),
                         args=[ast.Constant(value=idx)], keywords=[]), v)
        return self.visit(v)           # 非直命中 → 继续下降找嵌套直位（如 Compare）

    def visit_Expr(self, node: ast.Expr) -> ast.Expr:
        node.value = self._slot(node.value)
        return node

    def visit_Assign(self, node: ast.Assign) -> ast.Assign:
        if any(isinstance(t, ast.Name) and t.id == "__all__"
               for t in node.targets):
            return node                # __all__ 列表元素豁免（export 名是合同）
        node.value = self._slot(node.value)
        node.targets = [self.visit(t) for t in node.targets]
        return node

    def visit_Return(self, node: ast.Return) -> ast.Return:
        if node.value is not None:
            node.value = self._slot(node.value)
        return node

    def visit_Compare(self, node: ast.Compare) -> ast.Compare:
        node.left = self._slot(node.left)
        node.comparators = [self._slot(c) for c in node.comparators]
        return node

    # ---- 豁免区：整体不下降或只走允许子域 ----
    def _visit_body(self, node):
        """函数/类体：body[0] docstring 位置豁免，其余语句照常下降；
        decorator_list/bases/keywords/args/returns/type_params 全豁免。"""
        head = [node.body[0]] if (node.body and _is_docstring_stmt(node.body[0])) \
            else []
        node.body = head + [self.visit(s) for s in node.body[len(head):]]
        return node

    def visit_Module(self, node: ast.Module) -> ast.Module:
        head = [node.body[0]] if (node.body and _is_docstring_stmt(node.body[0])) \
            else []
        node.body = head + [self.visit(s) for s in node.body[len(head):]]
        return node

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        return self._visit_body(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        return self._visit_body(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.ClassDef:
        return self._visit_body(node)

    def visit_Lambda(self, node: ast.Lambda) -> ast.Lambda:
        node.body = self.visit(node.body)   # lambda 无 docstring；defaults 豁免
        return node

    def visit_JoinedStr(self, node: ast.JoinedStr) -> ast.JoinedStr:
        return node                    # f-string 整体及其内部豁免

    def visit_Match(self, node: ast.Match) -> ast.Match:
        node.subject = self.visit(node.subject)
        for case in node.cases:
            if case.guard is not None:
                case.guard = self.visit(case.guard)
            case.body = [self.visit(s) for s in case.body]   # pattern 豁免（编译期常量）
        return node

    def visit_AnnAssign(self, node: ast.AnnAssign) -> ast.AnnAssign:
        if node.value is not None:
            node.value = self.visit(node.value)   # annotation 豁免；值位非直位只下降
        return node

    def visit_AugAssign(self, node: ast.AugAssign) -> ast.AugAssign:
        if isinstance(node.target, ast.Name) and node.target.id == "__all__":
            return node                # __all__ += [...] 豁免
        return self.generic_visit(node)


def _encrypt_strings(tree: ast.Module, string_key: bytes, module_id: str) -> int:
    """字符串加密主流程：冲突检查 → 直值位替换收表 → stub 注入模块头。
    返回加密字符串数（表长）；无命中则不注入任何内容。"""
    if len(string_key) != 32:
        raise ValueError("string_key 必须为 32 字节（obf.key 语义）")
    _check_stub_name_conflicts(tree)
    cipher = _StringCipher(string_key, module_id)
    cipher.visit(tree)
    if cipher.table:
        ast.fix_missing_locations(tree)    # 手工构造的 Call 子树补齐位置字段
        stmts = _stub_statements(cipher.table, string_key, module_id)
        # stub 行号整体后移到原树最大行之后：不与业务行号交叠（traceback 不误导）
        base = 0
        for nd in ast.walk(tree):
            ln = getattr(nd, "lineno", None)
            if isinstance(ln, int) and ln > base:
                base = ln
        for st in stmts:
            ast.increment_lineno(st, base)
        # 插入点：docstring 之后 + 全部 __future__ import 之后（_TBL 先于一切使用点）
        idx = 1 if (tree.body and _is_docstring_stmt(tree.body[0])) else 0
        while (idx < len(tree.body) and isinstance(tree.body[idx], ast.ImportFrom)
               and tree.body[idx].module == "__future__"):
            idx += 1
        tree.body[idx:idx] = stmts
    return len(cipher.table)


def transform(tree: ast.Module, filename: str, *,
              protected: frozenset[str] = frozenset(),
              string_key: bytes | None = None,
              module_id: str | None = None) -> tuple[ast.Module, dict]:
    """AST 变换入口：返回 (变换后树, {"renamed": n, "stripped": m[, "strings": k]})。

    renamed = 实际改名 binding 数（逃逸豁免撤项不计）；stripped = 剥离 docstring 数；
    strings = 加密字符串数——仅 string_key 与 module_id 同时给出才启用字符串 pass
    （§13.3③ S6：改名 pass 先跑、字符串 pass 后跑；期1 调用方不传 → 行为与
    stats 形态不变）。symtable 需要源文本——用 ast.unparse 重建（结构等价 →
    作用域语义不变），原 tree 行号原样保留，symtable 仅用于作用域/候选分析。
    """
    root_block = symtable.symtable(ast.unparse(tree), filename, "exec")
    escape_names = _escape_exempt_names(tree)   # ★OB-1★ 先于候选分配：映射终态前置
    counter = [0]                             # 单文件全局计数器（禁用 set 迭代序）
    all_scopes: list[_Scope] = []
    root = _build_scopes(root_block, None, frozenset(protected), counter,
                         all_scopes, escape_names)
    renamer = _Renamer(root)
    tree = renamer.visit(tree)
    renamed = sum(len(s.mapping) for s in all_scopes)
    stats = {"renamed": renamed, "stripped": renamer.stripped}
    if string_key is not None and module_id is not None:
        stats["strings"] = _encrypt_strings(tree, string_key, module_id)
    return tree, stats


def compile_obfuscated(src_text: str, filename: str, *,
                       string_key: bytes | None = None,
                       module_id: str | None = None) -> tuple[types.CodeType, dict]:
    """源码 → 混淆 code object：parse → transform → compile(tree, "exec")。

    string_key/module_id 透传字符串加密 pass（都给才启用，§13.3③ S6）。
    co_filename=filename（调用方传包内相对路径，同时作 keystream 的 module_id）；
    compile(ast_obj) 保留原行号，docstring 剥离只删 Expr(Constant(str)) 节点，
    其余语句 lineno 不重排。
    """
    tree = ast.parse(src_text, filename)
    tree, stats = transform(tree, filename, string_key=string_key,
                            module_id=module_id)
    code = compile(tree, filename, "exec")
    return code, stats
