#!/usr/bin/env bash
# RUN2 真实 ._pth（<launcher 名>._pth @ launcher 目录）+ RUN3 同配置 PYTHONPATH 注入
#      RUN4 plain 模式（不设 program_name）负样本
set -eu
APP=/home/dev/work/spike/app
LIB=$APP/lib/libpython3.12.so.1.0
MYAPP=$APP/bin/myapp
PROBE2=/mnt/d/code/pack/scripts/spike/probe2.py

# 清掉三个候选，只留胜者（真实内容：stdlib + lib-dynload + 标记，相对 ._pth 所在目录=bin/）
rm -f "$APP/bin/python312._pth" "$APP/lib/libpython3.12.so.1.0._pth"
printf '../lib/python3.12\n../lib/python3.12/lib-dynload\n/tmp/mk_exe\n' > "$APP/bin/myapp._pth"

echo "######## RUN2: realistic myapp._pth + explicit program_name ########"
PYTHONPATH=/tmp/inject "$MYAPP" "$LIB" "pname:$MYAPP" "$PROBE2" || echo "RUN2_EXIT=$?"

echo "######## RUN4: plain mode (NO program_name), ._pth present (negative sample) ########"
"$MYAPP" "$LIB" "plain" /mnt/d/code/pack/scripts/spike/probe1.py || echo "RUN4_EXIT=$?"
