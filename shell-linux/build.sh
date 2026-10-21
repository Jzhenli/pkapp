#!/usr/bin/env bash
# ============================================================
# shell-linux launcher 构建（gcc，C17）
# 用法: ./build.sh [AppName] [PubHex] [PythonIncludeDir]
#   AppName   输出名（默认 myapp；= 部署进程标识，须与 ._pth 同名前缀）
#   PubHex    项目 Ed25519 公钥 raw hex（注入 /DPKAPP_PUB_HEX；缺省 =
#             manifest.c 内置根项目公钥，与 .pkapp/sign.key 配对）
#   PythonIncludeDir  PBS 运行时头文件目录（如 <pbs>/include/python3.12），
#             仅取 PyConfig 头不链接 libpython；缺省读环境变量 PYINC
# 产出: build/<AppName>
# 自检: ./build/<AppName> --selftest（算法向量）
#       ./build/<AppName> --selftest-spk <spk>（差分入口；pytest harness 见
#       tests/test_shell_contract.py，WSL 内从 pkapp 目录跑 python3 -m pytest）
# glibc 基线（D-2）：本机 gcc 仅开发验证；官方产物在 manylinux2014 容器编译
# ============================================================
set -euo pipefail
cd "$(dirname "$0")"

gcc --version | head -1   # R-L13 一行确认：开发验证 gcc ≥ 8；官方产物走容器 devtoolset

APPNAME=${1:-myapp}
PUBHEX=${2:-}
PYINC=${3:-${PYINC:-}}
WINSRC=../shell-windows/src

if [ -z "$PYINC" ]; then
  echo "[build] 缺少 PythonIncludeDir（PBS 头文件目录，PyConfig 头必须）" >&2
  echo "        用法: ./build.sh myapp '' ~/work/pbs-linux/python/include/python3.12" >&2
  exit 1
fi

PUBDEF=()
if [ -n "$PUBHEX" ]; then
  PUBDEF=(-DPKAPP_PUB_HEX="\"$PUBHEX\"")
fi

mkdir -p build

CFLAGS="-std=c17 -O2 -g -Wall -Wextra -Wno-unused-parameter -Wno-format-truncation -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -I$PYINC -I$WINSRC"
# 五模块 MSVC 遗留垫片：integrity.c 用 _snprintf（cl 专用名；所有调用点均配
# err[cap-1]=0 手工终结，snprintf 语义等价）。零改动复用共享模块，勿改源。
CFLAGS="$CFLAGS -D_snprintf=snprintf"

# 五模块直引 shell-windows/src（零复制零改动；阶段 0 已核验零 Linux 依赖）
for f in sha256 ed25519 spk manifest integrity; do
  gcc $CFLAGS "${PUBDEF[@]+"${PUBDEF[@]}"}" -c "$WINSRC/$f.c" -o "build/$f.o"
done
gcc $CFLAGS "${PUBDEF[@]+"${PUBDEF[@]}"}" -c src/main.c -o build/main.o

gcc build/sha256.o build/ed25519.o build/spk.o build/manifest.o \
    build/integrity.o build/main.o -o "build/$APPNAME" -lpthread -ldl

echo "[build] OK: build/$APPNAME"
