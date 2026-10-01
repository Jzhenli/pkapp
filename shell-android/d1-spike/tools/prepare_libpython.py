"""把 flet python-build 的 android 产物铺设进 D1 spike 工程。

用法: python prepare_libpython.py --dist <解压目录> --abi <abi> --app <app目录>
产出: app/src/main/jniLibs/<abi>/libpython*.so 等 + app/src/main/assets/stdlib.zip
"""
import argparse
import shutil
import zipfile
from pathlib import Path

ap = argparse.ArgumentParser()
ap.add_argument('--dist', required=True, help='flet 产物解压目录（含 libpython3.12.so 等）')
ap.add_argument('--abi', required=True, help='arm64-v8a / x86_64 / armeabi-v7a')
ap.add_argument('--app', required=True, help='工程 app 目录')
a = ap.parse_args()

dist, app = Path(a.dist), Path(a.app)
jni = app / 'src' / 'main' / 'jniLibs' / a.abi
jni.mkdir(parents=True, exist_ok=True)

for f in sorted(dist.iterdir()):
    if f.name != 'libpythonbundle.so':
        shutil.copy2(f, jni / f.name)

# stdlib 为 ABI 公共：只生成一次。
# 必须 STORED（无压缩）——android libpython 无内建 zlib，zipimport 读 DEFLATE 成员
# 会在 init_fs_encoding 阶段炸（zipimport.ZipImportError: zlib not available）。
assets = app / 'src' / 'main' / 'assets'
assets.mkdir(parents=True, exist_ok=True)
out = assets / 'stdlib.zip'
if not out.exists():
    z = zipfile.ZipFile(dist / 'libpythonbundle.so')
    with zipfile.ZipFile(out, 'w', zipfile.ZIP_STORED) as o:
        for n in z.namelist():
            if n.startswith('stdlib/') and not n.endswith('/'):
                o.writestr(n.removeprefix('stdlib/'), z.read(n))

print('jniLibs/%s:' % a.abi, [f.name for f in sorted(jni.iterdir())])
print('stdlib.zip entries:', len(zipfile.ZipFile(out).namelist()))
