#!/usr/bin/env bash
# ============================================================
# 阶段 1 冒烟：launcher 构建 + 部署树组装 + helloApp→ready 最小路径
# 在 WSL 内运行: bash shell-linux/tools/run_smoke.sh
# 可调: PBS=~/work/pbs-linux/python  SMOKE_OUT=~/work/smoke/myapp
#       SMOKE_ENC=1  → 加密链冒烟（子项 ②：keylib + codekey blob + app 密文树）
# ============================================================
set -euo pipefail
cd "$(dirname "$0")/.."          # shell-linux/

PBS=${PBS:-$HOME/work/pbs-linux/python}
SMOKE_OUT=${SMOKE_OUT:-$HOME/work/smoke/myapp}
export SMOKE_OUT                 # make_smoke_spk.py 读取同环境变量
SMOKE_ENC=${SMOKE_ENC:-0}
PYINC="$PBS/include/python3.12"

# --- 依赖自检（packager 签名需 cryptography；WSL Ubuntu 首跑装一次） ---
if ! python3 -c 'import cryptography' 2>/dev/null; then
  echo "[smoke] 安装 python3-cryptography（sudo）"
  sudo apt-get install -y python3-cryptography >/dev/null
fi

# --- 1. launcher 构建 ---
echo "=== [1/4] build launcher ==="
./build.sh myapp "" "$PYINC"

# --- 2. 冒烟 spk + 部署树 ---
echo "=== [2/4] build smoke spk (SMOKE_ENC=$SMOKE_ENC) ==="
if [ "$SMOKE_ENC" = "1" ]; then
  python3 tools/make_smoke_spk.py --encrypted
else
  python3 tools/make_smoke_spk.py
fi

echo "=== [3/4] assemble deploy tree ==="
mkdir -p "$SMOKE_OUT"
cp build/myapp "$SMOKE_OUT/myapp"
chmod +x "$SMOKE_OUT/myapp"
# D-5 定案：<launcher 名>._pth @ launcher 目录；条目相对 launcher 目录
# （_runtime 布局 = make_smoke_spk.py 顶部注释，阶段 2 assemble 对齐基准）
printf '_runtime/python312.zip\n_runtime/lib-dynload\n_runtime/deps\n' \
  > "$SMOKE_OUT/myapp._pth"

# --- 3. 冒烟运行 ---
echo "=== [4/4] run smoke (cold start ≤120s → ready → URL) ==="
READY="$SMOKE_OUT-ready"
rm -rf "$READY"
LOG=$(mktemp /tmp/smoke-myapp.XXXXXX.log)

MYAPP_DATA_DIR="$READY/data" MYAPP_CACHE_DIR="$READY/cache" \
  timeout 150 "$SMOKE_OUT/myapp" >"$LOG" 2>&1 &
PID=$!

cleanup() {
  kill "$PID" 2>/dev/null || true
  sleep 0.5
  kill -9 "$PID" 2>/dev/null || true
}
trap cleanup EXIT

echo "[smoke] launcher pid=$PID, log=$LOG"
echo "[smoke] 等待 ready 文件..."
for i in $(seq 1 120); do
  kill -0 "$PID" 2>/dev/null || break
  [ -f "$READY/cache/ready" ] && break
  sleep 1
done

if [ ! -f "$READY/cache/ready" ]; then
  echo "[smoke] FAIL: ready 未出现（150s）"
  echo "--- launcher log ---"; tail -40 "$LOG"
  exit 1
fi

echo "[smoke] READY 内容: $(cat "$READY/cache/ready")"
echo "--- launcher log（READY 行） ---"
grep -E "READY|ready|bootstrap|boot ok" "$LOG" | tail -10 || true

# 引导装载分支断言（子项 ② 加密链 / 子项 ① 明文直通）
if [ "$SMOKE_ENC" = "1" ]; then
  grep -q "codekey blob injected" "$LOG" \
    || { echo "[smoke] FAIL: 加密包未走 codekey 注入分支"; tail -40 "$LOG"; exit 1; }
else
  grep -q "codekey boot skipped" "$LOG" \
    || { echo "[smoke] FAIL: 明文包引导分支异常"; tail -40 "$LOG"; exit 1; }
fi

# 心跳 seq 递增确认（两拍）
S1=$(python3 -c "import json;print(json.load(open('$READY/cache/ready'))['seq'])")
sleep 6
S2=$(python3 -c "import json;print(json.load(open('$READY/cache/ready'))['seq'])")
echo "[smoke] 心跳 seq: $S1 -> $S2"

# /healthz 与业务 API 直击
PORT=$(python3 -c "import json;print(json.load(open('$READY/cache/ready'))['port'])")
echo "[smoke] /healthz: $(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/healthz")"
echo "[smoke] /api/hello: $(curl -s "http://127.0.0.1:$PORT/api/hello")"

if [ "$S2" -gt "$S1" ]; then
  if [ "$SMOKE_ENC" = "1" ]; then
    echo "=== [smoke] PASS: spk→验签→解压→完整性门→keylib pk_x4→codekey 注入→uvicorn→ready→心跳 全链通过（加密链） ==="
  else
    echo "=== [smoke] PASS: spk→验签→解压→完整性门→Python→uvicorn→ready→心跳 全链通过 ==="
  fi
else
  echo "=== [smoke] PARTIAL: ready 已出现但心跳未递增 ==="
  tail -20 "$LOG"
  exit 1
fi
