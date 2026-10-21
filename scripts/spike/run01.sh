#!/usr/bin/env bash
# RUN0 基线（无 ._pth）+ RUN1 三 ._pth 候选并置 → 判命中基准
set -eu
APP=/home/dev/work/spike/app
LIB=$APP/lib/libpython3.12.so.1.0
MYAPP=$APP/bin/myapp
PROBE=/mnt/d/code/pack/scripts/spike/probe1.py

echo "######## RUN0: baseline, NO ._pth (control) ########"
mkdir -p /tmp/pth_backup
mv "$APP/bin/myapp._pth" "$APP/bin/python312._pth" "$APP/lib/libpython3.12.so.1.0._pth" /tmp/pth_backup/
PYTHONPATH=/tmp/inject "$MYAPP" "$LIB" "pname:$MYAPP" "$PROBE" || echo "RUN0_EXIT=$?"
echo "######## RUN1: all three ._pth candidates present ########"
mv /tmp/pth_backup/myapp._pth /tmp/pth_backup/python312._pth "$APP/bin/"
mv /tmp/pth_backup/libpython3.12.so.1.0._pth "$APP/lib/"
PYTHONPATH=/tmp/inject "$MYAPP" "$LIB" "pname:$MYAPP" "$PROBE" || echo "RUN1_EXIT=$?"
