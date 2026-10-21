#!/usr/bin/env bash
# RUN5: zipimport stdlib + 第三方 deps 目录（fastapi/uvicorn/pydantic-core 真实 .so）
set -eu
APP=/home/dev/work/spike/app
LIB=$APP/lib/libpython3.12.so.1.0
MYAPP=$APP/bin/myapp

cd "$APP/lib/python3.12"
rm -f ../python312.zip
zip -qr ../python312.zip . -x 'lib-dynload/*' -x 'site-packages/*' -x 'config-*' -x 'test/*' -x 'idlelib/*' -x 'tkinter/*' -x 'turtledemo/*'
echo "ZIP_SIZE=$(du -h ../python312.zip | cut -f1)"

# 第三方 deps 散件目录（M3 真实负载：pydantic-core 含 .so 扩展）
~/work/pbs-linux/python/bin/pip install -q --target "$APP/deps" \
    -i https://pypi.tuna.tsinghua.edu.cn/simple fastapi uvicorn 2>&1 | tail -2 || true
ls "$APP/deps" | head -5

# ._pth 换成 M3 终态形态：stdlib zip + lib-dynload + deps + 标记
printf '../lib/python312.zip\n../lib/python3.12/lib-dynload\n../deps\n/tmp/mk_exe\n' > "$APP/bin/myapp._pth"

cat > /tmp/probe4.py <<'EOF'
import sys
print("ISOLATED =", sys.flags.isolated)
print("PATH_BEGIN")
for p in sys.path:
    print("  ", p)
print("PATH_END")
import encodings, email
print("ZIPIMPORT_OK encodings =", encodings.__file__)
import fastapi, uvicorn, pydantic
from pydantic_core import _pydantic_core
print("FASTAPI_OK", fastapi.__version__, "uvicorn", uvicorn.__version__, "pydantic", pydantic.VERSION)
print("THIRDPARTY_SO_OK", _pydantic_core.__file__)
EOF
"$MYAPP" "$LIB" "pname:$MYAPP" /tmp/probe4.py || echo "RUN5_EXIT=$?"
