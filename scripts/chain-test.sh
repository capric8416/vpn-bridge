#!/bin/bash
# End-to-end test of the whole chain without needing the real VM.
#
# A network namespace stands in for the Windows guest, and 198.51.100.5
# (TEST-NET-2) stands in for a host that only the "VPN" can reach: the address
# lives inside the namespace, so the only way to it is through the tunnel.
#
#   host app -> vpnbrtest (TUN) -> vpnbridge-host -> veth -> vpnbridge-vm -> target
#
# Usage: sudo-capable shell, then  ./scripts/chain-test.sh
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HOST_BIN="$ROOT/target/debug/vpnbridge-host"
VM_BIN="$ROOT/target/debug/vpnbridge-vm"
WORK="$(mktemp -d)"
NS=vpnbridge-test

if [ ! -x "$HOST_BIN" ] || [ ! -x "$VM_BIN" ]; then
  echo "build first: cargo build" >&2
  exit 1
fi

teardown() {
  sudo pkill -INT -f "$HOST_BIN" 2>/dev/null
  sudo ip netns pids $NS 2>/dev/null | xargs -r sudo kill 2>/dev/null
  sudo ip netns del $NS 2>/dev/null
  sudo ip link del vbr-h 2>/dev/null
}
trap 'teardown; rm -rf "$WORK"' EXIT
# Clear anything a previous aborted run left behind (but not $WORK, which was
# just created).
teardown 2>/dev/null

set -e
sudo ip netns add $NS
sudo ip link add vbr-h type veth peer name vbr-v
sudo ip link set vbr-v netns $NS
sudo ip addr add 10.99.0.1/24 dev vbr-h
sudo ip link set vbr-h up
sudo ip -n $NS addr add 10.99.0.2/24 dev vbr-v
sudo ip -n $NS link set vbr-v up
sudo ip -n $NS link set lo up
sudo ip -n $NS addr add 198.51.100.5/32 dev lo
set +e

cat > "$WORK/vm.toml" <<'EOF'
listen = "10.99.0.2:17321"
token = "t0k"
allow = ["198.51.100.0/24"]
EOF

cat > "$WORK/host.toml" <<'EOF'
routes = ["198.51.100.0/24"]

[server]
address = "10.99.0.2:17321"
token = "t0k"

[tun]
name = "vpnbrtest"
address = "10.211.0.1"
netmask = "255.255.255.0"

[dns]
listen = "127.0.0.1:15353"
upstream = ["198.51.100.5:53"]
EOF

# Services that only exist inside the namespace.
sudo ip netns exec $NS python3 - <<'PY' >"$WORK/targets.log" 2>&1 &
import socket, threading
def tcp():
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("198.51.100.5", 8080)); s.listen(5)
    while True:
        c, _ = s.accept()
        c.sendall(b"HTTP/1.0 200 OK\r\n\r\nintranet-ok"); c.close()
def udp(port, tag):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("198.51.100.5", port))
    while True:
        d, a = s.recvfrom(4096); s.sendto(tag + d, a)
threading.Thread(target=tcp, daemon=True).start()
threading.Thread(target=udp, args=(9090, b"udp:"), daemon=True).start()
udp(53, b"dns:")
PY
sudo ip netns exec $NS "$VM_BIN" --config "$WORK/vm.toml" --log debug >"$WORK/vm.log" 2>&1 &
sleep 1
sudo "$HOST_BIN" --config "$WORK/host.toml" --log debug >"$WORK/host.log" 2>&1 &
sleep 2

python3 - <<'PY'
import socket, sys, time
ok = []
def check(name, cond, detail=""):
    ok.append(cond)
    print(("PASS " if cond else "FAIL ") + name + ("  " + detail if detail else ""))

try:
    s = socket.create_connection(("198.51.100.5", 8080), timeout=8)
    s.sendall(b"GET / HTTP/1.0\r\n\r\n")
    data = s.recv(1024); s.close()
    check("tcp through the chain", b"intranet-ok" in data, repr(data[:32]))
except Exception as e:
    check("tcp through the chain", False, repr(e))

try:
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(8)
    u.sendto(b"hello", ("198.51.100.5", 9090))
    check("udp through the chain", u.recvfrom(4096)[0] == b"udp:hello")
except Exception as e:
    check("udp through the chain", False, repr(e))

try:
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(8)
    u.sendto(b"\xab\xcd-query", ("127.0.0.1", 15353))
    check("dns forwarder", u.recvfrom(4096)[0] == b"dns:\xab\xcd-query")
except Exception as e:
    check("dns forwarder", False, repr(e))

# A dead target cannot be refused (the handshake is already done locally), but
# it must be closed immediately rather than left hanging.
try:
    t0 = time.time()
    s = socket.create_connection(("198.51.100.5", 9999), timeout=8)
    s.settimeout(3)
    try:
        dead = s.recv(16) == b""
    except (ConnectionResetError, ConnectionAbortedError):
        dead = True
    except socket.timeout:
        dead = False
    check("dead target drops fast", dead, f"{time.time() - t0:.2f}s")
except (ConnectionRefusedError, ConnectionResetError) as e:
    check("dead target drops fast", True, type(e).__name__)

print(f"\n{sum(ok)}/{len(ok)} passed")
sys.exit(0 if all(ok) else 1)
PY
rc=$?

if [ $rc -ne 0 ]; then
  echo "=== host log ==="; tail -20 "$WORK/host.log"
  echo "=== vm log ===";   tail -20 "$WORK/vm.log"
fi
sudo pkill -INT -f "$HOST_BIN" 2>/dev/null
sleep 1
echo "routes after shutdown:"
ip route show | grep -E 'vpnbrtest|198.51.100' || echo "  (cleaned up)"
exit $rc
