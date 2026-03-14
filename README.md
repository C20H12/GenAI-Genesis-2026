# GenAI-Genesis-2026

A Go tool that intercepts TLS connections on a TPROXY port, performs man-in-the-middle, and prints request URLs and HTML response bodies.

## Build

```bash
go build -o mitm-proxy .
```

## Usage

```bash
# Run (needs root or CAP_NET_ADMIN + CAP_NET_RAW)
# ca.crt and ca.key are auto-generated on first run
sudo ./mitm-proxy
```

## iptables TPROXY Setup

```bash
# Mark packets and route them locally
sudo ip rule add fwmark 1 lookup 100
sudo ip route add local 0.0.0.0/0 dev lo table 100

# Redirect outgoing port-443 traffic to the proxy via TPROXY
sudo iptables -t mangle -A PREROUTING -p tcp --dport 443 -j TPROXY \
  --tproxy-mark 0x1/0x1 --on-port 8000
```

## Trust the CA

After the first run, trust `ca.crt` in your browser / system certificate store so the forged certificates are accepted.