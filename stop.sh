#!/usr/bin/env bash
# 停掉 start.sh 起的所有服务（dispatcher / 靶机 / claude 子进程 / serve）。
# 注意：serve 是一次性的，停了要重新起；DB 和项目数据保留。
set -uo pipefail
cd "$(dirname "$0")"

log() { echo "[stop.sh] $*"; }

pkill -9 -f "cairn dispatch" 2>/dev/null && log "✓ 停 dispatcher" || log "  dispatcher 未在跑"
pkill -9 -f "claude --session-id" 2>/dev/null && log "✓ 停 claude 子进程" || log "  无 claude 子进程"
pkill -9 -f "vuln_udp_server" 2>/dev/null && log "✓ 停靶机" || log "  靶机未在跑"
pkill -9 -f "cairn serve" 2>/dev/null && log "✓ 停 cairn serve" || log "  serve 未在跑"

log "完成。项目数据保留在 DB，下次 start.sh 会复用。"
