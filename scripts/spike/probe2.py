import os
import sys
import sysconfig

print("ISOLATED =", sys.flags.isolated)
print("SAFE_PATH =", sys.flags.safe_path)
print("NO_SITE =", sys.flags.no_site)
print("EXE =", sys.executable)
print("PREFIX =", sys.prefix)
print("BASE_PREFIX =", sys.base_prefix)
print("PLATLIBDIR =", sys.platlibdir)
print("PATH_BEGIN")
for p in sys.path:
    print("  ", p)
print("PATH_END")
print("PYTHONPATH_ENV =", os.environ.get("PYTHONPATH"))
print("PYTHONPATH_IN_PATH =", os.environ.get("PYTHONPATH") in sys.path)

# C 扩展可加载（§9.1④：dlopen(RTLD_NOW|RTLD_GLOBAL) 口径下的 lib-dynload 扩展）
for mod in ("zlib", "_json", "math", "unicodedata"):
    try:
        m = __import__(mod)
        print("EXT_OK", mod, getattr(m, "__file__", "(builtin)"))
    except Exception as e:
        print("EXT_FAIL", mod, repr(e))

# sysconfig / 模块路径记录（spike 交付物）
print("SYSCONFIG_PATHS_BEGIN")
for k, v in sorted(sysconfig.get_paths().items()):
    print(f"  {k} = {v}")
print("SYSCONFIG_PATHS_END")
import encodings
print("ENCODINGS =", encodings.__file__)
