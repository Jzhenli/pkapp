#!/usr/bin/env bash
# R-L22 实测：下载 PBS armv7 构件 → grep 实测 glibc 底线 + 查共享 libpython + 布局
set -u
cd ~/work || exit 1
NAME="cpython-3.12.14+20260929-armv7-unknown-linux-gnueabihf-install_only_stripped.tar.gz"
URL="https://github.com/astral-sh/python-build-standalone/releases/download/20260929/$NAME"

if [ ! -s cpython-armv7.tar.gz ]; then
    if [ -s '/mnt/d/WSL/cpython-3.12.14+20260929-armv7-unknown-linux-gnueabihf-install_only_stripped.tar.gz' ]; then
        cp '/mnt/d/WSL/cpython-3.12.14+20260929-armv7-unknown-linux-gnueabihf-install_only_stripped.tar.gz' cpython-armv7.tar.gz
    else
        for m in "" "https://gh-proxy.com/" "https://ghfast.top/" "https://ghproxy.net/"; do
            echo "== trying [${m:-direct}]"
            if curl -fL --retry 2 --connect-timeout 15 -o cpython-armv7.tar.gz "$m$URL"; then
                break
            fi
            rm -f cpython-armv7.tar.gz
        done
    fi
fi
[ -s cpython-armv7.tar.gz ] || { echo "ARMV7_DOWNLOAD_FAILED"; exit 1; }
ls -la cpython-armv7.tar.gz

rm -rf pbs-armv7
mkdir -p pbs-armv7
tar -xzf cpython-armv7.tar.gz -C pbs-armv7
R=pbs-armv7/python
echo "== top-level =="
ls "$R"
echo "== libpython =="
ls -la "$R/lib"/libpython* 2>/dev/null || echo "NO_LIBPYTHON"
echo "== glibc version refs in libpython =="
grep -ao 'GLIBC_2\.[0-9]*' "$R/lib/libpython3.12.so.1.0" 2>/dev/null | sort -Vu | tail -3
echo "== glibc version refs in stdlib lib-dynload (max across all .so) =="
find "$R/lib" -name '*.so*' -type f 2>/dev/null | while read -r f; do
    grep -ao 'GLIBC_2\.[0-9]*' "$f" 2>/dev/null
done | sort -Vu | tail -3
echo "== arch check =="
file "$R/lib/libpython3.12.so.1.0" 2>/dev/null | head -1
