#!/usr/bin/env bash
# 搭建 D-5 实验环境：模仿真实部署布局（bin/ 放 launcher，lib/ 放 libpython + stdlib）
set -eu
W=~/work/spike
APP=$W/app
rm -rf "$W"
mkdir -p "$APP/bin" "$APP/lib"

P=~/work/pbs-linux/python
cp -a "$P/lib/python3.12"       "$APP/lib/python3.12"
cp -a "$P/lib/libpython3.12.so.1.0" "$APP/lib/"
cp -a "$P/lib/libpython3.12.so"     "$APP/lib/"
cp -a "$P/lib/libpython3.so"        "$APP/lib/"
cp -a "$P/include"              "$APP/include"

# harness（dlopen 不链接；用 PBS 自带头编译保证 PyConfig 布局一致）
gcc -std=c17 -I"$APP/include/python3.12" \
    /mnt/d/code/pack/scripts/spike/embed.c -o "$APP/bin/myapp" -ldl

# 标记目录（各 ._pth 候选指向不同目录，凭 sys.path 输出即可判命中）
mkdir -p /tmp/mk_exe /tmp/mk_lib /tmp/mk_py312 /tmp/inject
echo "MARK_EXE"  > /tmp/mk_exe/__marker.py
echo "MARK_LIB"  > /tmp/mk_lib/__marker.py
echo "MARK_PY312" > /tmp/mk_py312/__marker.py
echo "INJECT_SHOULD_NOT_APPEAR" > /tmp/inject/__inject_probe.py

# ._pth 三个候选全部预置（内容各指向不同标记目录）
printf '/tmp/mk_exe\n'   > "$APP/bin/myapp._pth"
printf '/tmp/mk_lib\n'   > "$APP/lib/libpython3.12.so.1.0._pth"
printf '/tmp/mk_py312\n' > "$APP/bin/python312._pth"

echo "SETUP_OK at $APP"
