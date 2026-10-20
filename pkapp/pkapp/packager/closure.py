"""B.s 原生依赖闭包自检（拆分前居于 assemble；G7 构建期闸门）。"""
from __future__ import annotations

import os

from . import pe
from .errors import BuildError

# B.s 系统白名单（真 PBS 3.12.14 实测回填：Cabinet/msi 来自 _msi.pyd，PROPSYS 来自 _wmi.pyd）
_SYSTEM_DLLS = frozenset("""
kernel32 user32 gdi32 shell32 advapi32 ole32 oleaut32 ws2_32 bcrypt ncrypt crypt32
version ntdll ucrtbase msvcrt vcruntime140 vcruntime140_1 msvcp140 comctl32 comdlg32
winmm iphlpapi powrprof shlwapi userenv dbghelp psapi secur32 wintrust setupapi
netapi32 dnsapi mpr uuid rpcrt4 sspicli kernelbase
cabinet msi propsys imm32
""".split())


def _is_system_dll(name: str) -> bool:
    n = name.lower().removesuffix(".dll")
    return n in _SYSTEM_DLLS or n.startswith(("api-ms-win-", "ext-ms-"))


def check_closure(stage: str, python_dll: str,
                  extra_dirs: tuple[str, ...] = ()) -> None:
    """B.s 依赖闭包自检：pyd/.dll 的传递依赖必须闭环（缺 → 构建失败，G7）。

    解析域 = DLLs/ ∪ stage 根 ∪ extra_dirs（★v1.3★ Q5：app/ 纳入扫描域，为③ pyd
    立项预留健康检查位）——真 PBS 实测教训：pyd 依赖 python312.dll，只扫 DLLs/
    会误报缺口。
    """
    dlls_dir = os.path.join(stage, "DLLs")
    present: dict[str, str] = {}   # 小写文件名 → 完整路径
    for fn in os.listdir(dlls_dir):
        if fn.lower().endswith((".pyd", ".dll")):
            present[fn.lower()] = os.path.join(dlls_dir, fn)
    for fn in os.listdir(stage):
        if fn.lower().endswith(".dll"):
            present.setdefault(fn.lower(), os.path.join(stage, fn))
    for extra in extra_dirs:
        for dirpath, _dirnames, filenames in os.walk(extra):
            for fn in filenames:
                if fn.lower().endswith((".pyd", ".dll")):
                    present.setdefault(fn.lower(), os.path.join(dirpath, fn))

    stack = [p for k, p in present.items() if k.endswith(".pyd")]
    pdl = python_dll.lower()
    if pdl in present:
        stack.append(present[pdl])
    seen, missing = set(), set()
    while stack:
        path = stack.pop()
        cur = os.path.basename(path)
        if cur.lower() in seen:
            continue
        seen.add(cur.lower())
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError as e:
            raise BuildError(f"闭包扫描读取失败 {cur}: {e}") from e
        try:
            imports = pe.read_imports(data)
        except pe.PEError as e:
            raise BuildError(f"{cur} 不是可解析 PE（B.s 要求二进制层闭包）: {e}") from e
        for imp in imports:
            key = imp.lower()
            if _is_system_dll(key):
                continue
            dep = present.get(key)
            if dep:
                stack.append(dep)
            else:
                missing.add(imp)
    if missing:
        raise BuildError("原生依赖闭包不完整（B.s/G7）: 缺 " + ", ".join(sorted(missing)))
