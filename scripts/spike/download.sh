#!/usr/bin/env bash
# 阶段 0 spike：下载 PBS cpython 3.12.14 x86_64 linux gnu（tag 对齐 windows pin = 20260929）
set -u
cd ~/work || exit 1

URL_PATH="https://github.com/astral-sh/python-build-standalone/releases/download/20260929/cpython-3.12.14+20260929-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz"

if [ -s cpython-linux.tar.gz ]; then
    echo "SKIP: already downloaded"
    exit 0
fi

for m in "" "https://gh-proxy.com/" "https://ghfast.top/" "https://ghproxy.net/"; do
    echo "== trying [${m:-direct}]"
    if curl -fL --retry 2 --connect-timeout 15 -o cpython-linux.tar.gz "$m$URL_PATH"; then
        echo "DOWNLOAD_OK"
        break
    fi
    rm -f cpython-linux.tar.gz
done

ls -la cpython-linux.tar.gz 2>/dev/null
