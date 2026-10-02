"""Android 原生扩展桥（★v1.2★ W^X 形态，§4.2 步骤 2 的完整实现）。

release 安装器只抽 `lib*.so`（debuggable 豁免不可依赖——实测 Honor Magic6：
release 只落 5 个 lib 前缀件，55 个扩展模块缺席 → No module named '_struct'）。
故 jniLibs 内扩展模块一律机械加 lib 前缀落盘（array→libarray、
_struct→lib_struct，"lib"+原名直接拼接），NdkExtFinder 把 `import _struct`
重写为 lib{fullname}{EXT_SUFFIX} 的 ExtensionFileLoader（serious_python 蓝本）。

导入纪律（本模块必须能在 `import applocal` 最早期生效，且自身不能触发任何
扩展模块导入）：
- 只允许 glob / os / sys / importlib.machinery / importlib.util——全是纯 Python；
  不 import importlib.abc（拉 pathlib → urllib.parse → math，math 也是扩展件，
  鸡生蛋）；meta_path 只鸭子要求 find_spec。
- ctypes（拉 _ctypes 扩展件）只能在 register() 内、finder 注册之后导入。
"""
import glob
import importlib.machinery
import importlib.util
import os
import sys

__all__ = ["NdkExtFinder", "register"]


class NdkExtFinder:
    """lib*.so 命名的 CPython 扩展模块 → 原名导入（鸭子类型 finder）。"""

    def __init__(self, lib_dir: str) -> None:
        self._dir = lib_dir

    def find_spec(self, fullname, path=None, target=None):
        if path is not None or target is not None:
            return None                                 # 仅顶层扩展模块
        # 纪律：find_spec 内禁止任何 import（find_spec 会在其它模块导入中途被
        # 递归调用——实测 import sysconfig 直接 RecursionError）。
        # EXTENSION_SUFFIXES 取自模块级 machinery，无新导入。
        p = None
        for suf in importlib.machinery.EXTENSION_SUFFIXES:
            q = os.path.join(self._dir, f"lib{fullname}{suf}")
            if os.path.isfile(q):
                p = q
                break
        if p is None:                                   # 兜底：lib<name>*.so（tag 差异）
            g = sorted(glob.glob(os.path.join(self._dir, f"lib{fullname}.*so")))
            p = g[0] if g else None
        if p is None:
            return None
        loader = importlib.machinery.ExtensionFileLoader(fullname, p)
        return importlib.util.spec_from_file_location(fullname, p, loader=loader)


def register(lib_dir: str) -> None:
    """注册 finder（幂等）→ 预载依赖件（RTLD_GLOBAL，可失败）。

    顺序敏感：finder 先行，ctypes（→ _ctypes 扩展件）随后才能导入。
    """
    if not lib_dir or not os.path.isdir(lib_dir):
        return
    if not any(isinstance(f, NdkExtFinder) for f in sys.meta_path):
        pf = next((i for i, f in enumerate(sys.meta_path)
                   if f is importlib.machinery.PathFinder), len(sys.meta_path))
        sys.meta_path.insert(pf, NdkExtFinder(lib_dir))
    try:
        import ctypes
        for so in sorted(glob.glob(os.path.join(lib_dir, "*.so"))):
            try:
                ctypes.CDLL(so, mode=ctypes.RTLD_GLOBAL)   # _ssl 依赖 libcrypto_python 等
            except OSError:
                pass
    except ImportError:                                    # _ctypes 自身也是扩展件
        pass
