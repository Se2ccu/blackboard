#!/usr/bin/env bash
# 一键启动 UDP PoC 漏洞挖掘闭环。
# 幂等：已起的服务不重复起；已有 active 的 UDP 项目直接复用，不新建。
#
# 全部后台起，脚本立刻退出。之后：
#   web 看图：       http://127.0.0.1:8000/
#   看实时推理：    uv run python tools/render_session.py --live
#   看归档：        uv run python tools/render_session.py --latest
#   dispatcher 日志：tail -f /tmp/cairn-dispatch.log
#
# 用法：
#   ./start.sh              默认起 UDP PoC 工程
#   ./start.sh --fresh      先停掉所有旧进程再起（DB 不清，项目复用）
set -euo pipefail
cd "$(dirname "$0")"

SERVE_URL="http://127.0.0.1:8000"
DISPATCH_LOG="/tmp/cairn-dispatch.log"
TARGET_BIN="targets/bpftrace_udp/vuln_udp_server"
TARGET_PORT=9090

log() { echo "[start.sh] $*"; }

is_listening() { ss -uln 2>/dev/null | grep -q ":$1 "; }
serve_up() { curl -sf "$SERVE_URL/projects" >/dev/null 2>&1; }
proc_running() { pgrep -f "$1" >/dev/null 2>&1; }

# --fresh: 先清掉所有相关进程
if [[ "${1:-}" == "--fresh" ]]; then
  log "--fresh: 停掉旧 dispatcher / 靶机 / claude 子进程"
  pkill -9 -f "cairn dispatch" 2>/dev/null || true
  pkill -9 -f "claude --session-id" 2>/dev/null || true
  pkill -9 -f "vuln_udp_server" 2>/dev/null || true
  sleep 1
fi

# 1. 编译靶机二进制（已有就跳过）
if [[ ! -x "$TARGET_BIN" ]]; then
  log "编译靶机二进制..."
  gcc -O0 -g -Wall -o "$TARGET_BIN" targets/bpftrace_udp/vuln_udp_server.c
fi

# 2. cairn serve（一次性，已起就跳过）
if serve_up; then
  log "✓ cairn serve 已在跑"
else
  log "启动 cairn serve（后台）..."
  nohup uv run --project cairn cairn serve > /tmp/cairn-serve.log 2>&1 &
  # 等它起来
  for i in $(seq 1 30); do
    serve_up && break
    sleep 0.5
  done
  if ! serve_up; then
    log "✗ cairn serve 起不来，看 /tmp/cairn-serve.log"; exit 1
  fi
  log "✓ cairn serve 已起"
fi

# 3. 靶机 UDP 服务（每次起，已在监听就跳过）
if is_listening "$TARGET_PORT"; then
  log "✓ 靶机已在监听 :$TARGET_PORT"
else
  log "启动靶机 $TARGET_BIN :$TARGET_PORT（后台）..."
  nohup "$TARGET_BIN" "$TARGET_PORT" > /tmp/cairn-target.log 2>&1 &
  for i in $(seq 1 10); do
    is_listening "$TARGET_PORT" && break
    sleep 0.3
  done
  if ! is_listening "$TARGET_PORT"; then
    log "✗ 靶机起不来，看 /tmp/cairn-target.log"; exit 1
  fi
  log "✓ 靶机已起"
fi

# 4. UDP PoC 项目（复用 active 的，没有才建）
PROJECT_ID=$(curl -s "$SERVE_URL/projects" 2>/dev/null | python3 -c "
import sys, json
try:
    projs = json.load(sys.stdin)
except Exception:
    print('', end=''); sys.exit()
for p in projs:
    if p.get('status') == 'active' and 'PoC' in p.get('title',''):
        print(p['id']); break
" 2>/dev/null)
if [[ -n "$PROJECT_ID" ]]; then
  log "✓ 复用现有 active 项目 $PROJECT_ID"
else
  log "创建 UDP PoC 项目..."
  OUT=$(uv run --project cairn python create_target_project.py 2>&1) || { echo "$OUT"; exit 1; }
  PROJECT_ID=$(echo "$OUT" | grep -oP 'id=\Kproj_\d+' | head -1)
  log "✓ 新建项目 $PROJECT_ID"
fi

# 5. dispatcher（长跑，已起就跳过）
if proc_running "cairn dispatch"; then
  log "✓ dispatcher 已在跑"
else
  log "启动 dispatcher（后台，日志 $DISPATCH_LOG）..."
  nohup uv run --project cairn cairn dispatch --config dispatch_local.yaml --log-level info > "$DISPATCH_LOG" 2>&1 &
  for i in $(seq 1 10); do
    proc_running "cairn dispatch" && break
    sleep 0.3
  done
  proc_running "cairn dispatch" && log "✓ dispatcher 已起" || { log "✗ dispatcher 起不来，看 $DISPATCH_LOG"; exit 1; }
fi

echo
echo "=========================================="
log "全部就绪。项目: $PROJECT_ID"
echo "  web 看图:        $SERVE_URL/"
echo "  实时推理:         uv run python tools/render_session.py --live"
echo "  归档轨迹:         uv run python tools/render_session.py --latest"
echo "  dispatcher 日志:  tail -f $DISPATCH_LOG"
echo "  项目图:           curl -s $SERVE_URL/projects/$PROJECT_ID/export"
echo "  停止全部:         ./stop.sh"
echo "=========================================="
