#!/usr/bin/env bash
# linux 打包验收（package linux 产物端到端）：解包 → 部署树清点 → 启动 →
# 进程标题 → ready → healthz → 鉴权门 → 收尾。WSL/Linux 内运行。
# 用法: bash verify_hello.sh <tar.gz 路径> [应用名]   （应用名默认 hello）
set -u
TAR=${1:?用法: verify_hello.sh <tar.gz> [应用名]}
APP=${2:-hello}
WORK=/tmp/pkapp-verify-$$

rm -rf "$WORK" && mkdir -p "$WORK"
tar xzf "$TAR" -C "$WORK"
cd "$WORK/$APP"
# 残留 ready（上一轮验证死端口）会让探测假通过——启动前必清
rm -f "$HOME/.local/share/$APP/ready" "$HOME/.cache/$APP/ready" "$WORK/$APP/ready"
ls -la | awk '{print $1, $9}'

./"$APP" &
PID=$!
sleep 0.5
ps -p $PID -o pid=,comm= 2>/dev/null && echo "PROCTITLE: $(ps -p $PID -o comm=)" || { echo "launcher exited early"; exit 1; }

READY=""
PORT=""
for i in $(seq 1 90); do
  for d in "$HOME/.local/share/$APP" "$HOME/.cache/$APP" "$WORK/$APP"; do
    [ -z "$READY" ] && [ -f "$d/ready" ] && READY="$d/ready"
  done
  if [ -n "$READY" ]; then
    PORT=$(grep -o '"port": *[0-9]*' "$READY" | grep -o '[0-9]*$')
    RFLAG=$(grep -o '"ready": *true' "$READY")
    [ -n "$PORT" ] && [ -n "$RFLAG" ] && break
  fi
  kill -0 $PID 2>/dev/null || { echo "launcher died"; exit 1; }
  sleep 1
done
[ -n "$PORT" ] || { echo "ready not lit in 90s"; exit 1; }
echo "READY=$READY PORT=$PORT"

H=""
for i in 1 2 3 4 5; do
  H=$(curl -s -m 5 -w "|HTTP:%{http_code}" "http://127.0.0.1:$PORT/healthz")
  [ "$H" = '|HTTP:200' ] && break
  sleep 1
done
echo "HEALTHZ: $H"
A=$(curl -s -m 5 -o /dev/null -w "%{http_code}" "http://127.0.0.1:$PORT/api/hello")
echo "API /api/hello: HTTP $A (expect 401/403 behind auth gate)"

kill $PID 2>/dev/null
[[ "$H" == *'|HTTP:200' ]] && [ "$A" != "200" ] && echo "VERIFY-OK" || { echo "VERIFY-FAILED"; exit 1; }
