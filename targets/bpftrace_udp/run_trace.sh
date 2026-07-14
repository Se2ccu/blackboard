#!/usr/bin/env bash
# run_trace.sh - 一键联合运行：bpftrace + udp_receiver + nc sender
# 用法： sudo ./run_trace.sh
set -u

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

LOG="$ROOT/trace_output.log"

# 1) 启动 bpftrace（后台），输出重定向到日志
echo "[run] starting bpftrace -> $LOG"
bpftrace -B none udp_recv_trace.bt >"$LOG" 2>&1 &
BT_PID=$!

# 2) 等 bpftrace 编译 + attach 完成
echo "[run] waiting bpftrace to attach (3s)..."
sleep 3

# 3) 启动 udp_receiver，占 9000 端口
echo "[run] starting udp_receiver"
./udp_receiver 9000 >recv_output.log 2>&1 &
RX_PID=$!
sleep 0.5

# 4) 用 nc 发 3 个 UDP 包
echo "[run] sending 3 udp packets via nc..."
for i in 1 2 3; do
    printf "bpftrace-pkt-%d\n" "$i" | nc -u -w1 127.0.0.1 9000
    sleep 0.4
done

# 5) 收尾
sleep 1
echo "[run] stopping bpftrace (PID=$BT_PID) and udp_receiver (PID=$RX_PID)"
kill -INT "$BT_PID" 2>/dev/null
sleep 1
kill "$RX_PID" 2>/dev/null
wait 2>/dev/null

echo
echo "===== recv_output.log ====="
cat recv_output.log
echo
echo "===== trace_output.log (first 200 lines) ====="
head -200 "$LOG"
echo
echo "===== trace_output.log total lines ====="
wc -l "$LOG"
