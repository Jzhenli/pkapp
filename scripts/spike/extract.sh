#!/usr/bin/env bash
# 解压 PBS 构件 + R-L8 断言（共享 libpython3.12.so.1.0 存在）
set -eu
mkdir -p ~/work/pbs-linux
tar -xzf '/mnt/d/WSL/cpython-3.12.14+20260929-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz' \
    -C ~/work/pbs-linux

R=~/work/pbs-linux/python
echo "== top-level =="
ls "$R"
echo "== bin =="
ls "$R/bin"
echo "== lib (libpython*) =="
ls -la "$R/lib"/libpython* 2>/dev/null || echo "NO_LIBPYTHON_IN_LIB"
echo "== find libpython anywhere =="
find "$R" -name 'libpython3.12*' -exec ls -la {} \;
