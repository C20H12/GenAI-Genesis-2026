# GenAI-Genesis-2026

Transparent MITM TLS proxy with async LLM-powered fraud detection. Intercepts HTTPS via Linux TPROXY, inspects HTML responses, scores them through OpenRouter, and stores results in SQLite.

## Build & Run

```bash
echo 'OPENROUTER_API_KEY=sk-or-...' > .env
go build -o mitm .
sudo setcap 'cap_net_admin,cap_net_raw+ep' ./mitm
./mitm   # listens :8000 (TPROXY) and :8001 (HTTP CONNECT)
```

A `ca.crt` is generated on first run — install it as a trusted CA on client devices.

## Raspberry Pi Deployment (Secondary Router)

Cross-compile and copy to the Pi:

```bash
GOOS=linux GOARCH=arm64 go build -o mitm .
scp mitm .env ca.crt ca.key pi@<pi-ip>:~/mitm/
```

On the Pi, enable IP forwarding and NAT:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

Set LAN clients' default gateway to the Pi's IP.

## TPROXY Setup (`*:443` TCP)

Redirect all forwarded TLS traffic to the proxy without altering the destination address:

```bash
# Policy routing — deliver marked packets locally
sudo ip rule  add fwmark 0x1 lookup 100
sudo ip route add local 0.0.0.0/0 dev lo table 100

# TPROXY — intercept TCP :443 and hand to proxy on :8000
sudo iptables -t mangle -A PREROUTING \
  -p tcp --dport 443 \
  -j TPROXY --on-port 8000 --tproxy-mark 0x1/0x1
```

Persist with `sudo netfilter-persistent save` (install `iptables-persistent`).
