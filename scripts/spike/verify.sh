#!/usr/bin/env bash
# 拉取 PBS 20260929 官方 SHA256SUMS 并核对 linux x86_64 install_only_stripped 行
set -u
TARGET="ef605200f8174e87ecfc308e52a88127543f85dd5c940dc5e92cab244b98a003"
NAME="cpython-3.12.14+20260929-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz"

ok=""
for m in "" "https://gh-proxy.com/" "https://ghfast.top/" "https://ghproxy.net/"; do
    if curl -fsL --connect-timeout 15 "${m}https://github.com/astral-sh/python-build-standalone/releases/download/20260929/SHA256SUMS" -o /tmp/SHA256SUMS 2>/dev/null; then
        ok="${m:-direct}"
        break
    fi
done

if [ -z "$ok" ]; then
    echo "SHA256SUMS_FETCH_FAILED"
    exit 1
fi

want=$(grep -F "$NAME" /tmp/SHA256SUMS | awk '{print $1}')
echo "source=[$ok]"
echo "expect=$want"
echo "actual=$TARGET"
if [ "$want" = "$TARGET" ]; then
    echo "SHA256_MATCH"
else
    echo "SHA256_MISMATCH"
    exit 2
fi
