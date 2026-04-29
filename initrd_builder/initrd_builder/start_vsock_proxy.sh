#!/bin/bash
# start_host.sh

set -e

# 2. 启动 socat：VSOCK:50051 -> localhost:50052
echo "Starting VSOCK proxy (VSOCK:50051 -> localhost:50052)..."
socat -d -d -v VSOCK-LISTEN:50051,reuseaddr,fork TCP-CONNECT:localhost:50052 2>&1 | tee /tmp/socat.log &
SOCAT_PID=$!
sleep 1

if ! kill -0 $SOCAT_PID 2>/dev/null; then
    echo "✗ Failed to start VSOCK proxy"
    kill $SERVER_PID 2>/dev/null
    exit 1
fi
echo "✓ VSOCK proxy started (PID: $SOCAT_PID)"

# 验证
echo ""
echo "=== Verification ==="
echo "gRPC server port:"
ss -tlnp | grep 50052 || echo "  Not listening on 50052"

echo "VSOCK listener:"
ss -tlnp | grep 50051 || echo "  No TCP listener on 50051 (VSOCK doesn't show in TCP)"

echo ""
echo "✓ Host ready: VM can connect via VSOCK:2:50051"

# 保存 PIDs 用于清理
echo $SERVER_PID > /tmp/server.pid
echo $SOCAT_PID > /tmp/socat.pid

# 清理函数
cleanup() {
    echo ""
    echo "Shutting down..."
    kill $(cat /tmp/socat.pid) 2>/dev/null || true
    kill $(cat /tmp/server.pid) 2>/dev/null || true
    rm -f /tmp/server.pid /tmp/socat.pid
    exit 0
}
trap cleanup SIGINT SIGTERM

echo "Press Ctrl+C to stop..."
wait