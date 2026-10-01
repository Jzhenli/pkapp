"""铺设 flet python-build android 产物 → M2 壳工程（shell/）。

用法: python prepare_runtime.py --dist <flet产物目录> --abi arm64-v8a --app <壳工程 app 目录>

产出:
  app/src/main/jniLibs/<abi>/  libpython3NN.so + 支持库（libssl/libcrypto/libsqlite3）
                               + bundle 内 modules/*.so 平铺（56 个扩展模块）。
                               运行期经 MYAPP_NATIVE_LIB_DIR=nativeLibraryDir 被 applocal
                               _inject_native 预载 + sys.path 注入（协议 §4.4 W^X 形态：
                               so 走系统 dlopen，绝不从可写目录加载）。
  app/src/main/assets/stdlib.zip  bundle 内 stdlib/* → ZIP_STORED。
                               android libpython 无内建 zlib：DEFLATE 成员会在
                               init_fs_encoding 阶段炸（D1 实测硬约束）。
stdlib.zip 为 ABI 公共：仅首个 ABI 生成。
"""
import argparse
import shutil
import zipfile
from pathlib import Path

ap = argparse.ArgumentParser()
ap.add_argument('--dist', required=True, help='flet 产物目录（含 libpython3.12.so 等）')
ap.add_argument('--abi', required=True, help='arm64-v8a / x86_64 / armeabi-v7a')
ap.add_argument('--app', required=True, help='壳工程 app 目录')
a = ap.parse_args()

dist, app = Path(a.dist), Path(a.app)
jni = app / 'src' / 'main' / 'jniLibs' / a.abi
jni.mkdir(parents=True, exist_ok=True)

# 1) 顶层支持库 + libpython 本体（bundle 除外：其内容拆铺到 jniLibs 与 assets）
for f in sorted(dist.iterdir()):
    if f.name != 'libpythonbundle.so':
        shutil.copy2(f, jni / f.name)

bundle = zipfile.ZipFile(dist / 'libpythonbundle.so')
names = bundle.namelist()

# 2) modules/*.so → jniLibs 平铺（扩展模块；<name>.cpython-312.so 后缀与
#    importlib EXTENSION_SUFFIXES 匹配，sys.path 注入后直接 import）
mods = [n for n in names if n.startswith('modules/') and n != 'modules/'
        and not n.endswith('/')]
for n in mods:
    (jni / Path(n).name).write_bytes(bundle.read(n))

# 3) stdlib/* → assets/stdlib.zip（ZIP_STORED；ABI 公共，只生成一次）
assets = app / 'src' / 'main' / 'assets'
assets.mkdir(parents=True, exist_ok=True)
out = assets / 'stdlib.zip'
if not out.exists():
    with zipfile.ZipFile(out, 'w', zipfile.ZIP_STORED) as o:
        for n in names:
            if n.startswith('stdlib/') and not n.endswith('/'):
                o.writestr(n.removeprefix('stdlib/'), bundle.read(n))

print('jniLibs/%s: %d files (top=%s + %d modules)' % (
    a.abi, len(list(jni.iterdir())),
    [f.name for f in sorted(dist.iterdir()) if f.name != 'libpythonbundle.so'],
    len(mods)))
if out.exists():
    print('assets/stdlib.zip entries:', len(zipfile.ZipFile(out).namelist()))
