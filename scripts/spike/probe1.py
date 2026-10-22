import os
import sys

print("ISOLATED =", sys.flags.isolated)
print("EXE =", sys.executable)
print("PREFIX =", sys.prefix)
print("BASE_PREFIX =", sys.base_prefix)
print("PATH_BEGIN")
for p in sys.path:
    print("  ", p)
print("PATH_END")
print("PYTHONPATH_ENV =", os.environ.get("PYTHONPATH"))
