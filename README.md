# GenAI-Genesis-2026

## Inspiration
- Traditional fraud detection relies on software that runs on the client's device. However, the effectiveness of this approach is undermined by the stable running of the software on numerous different machines, plus the challenges with spreading awareness and getting users to actually install the detection software. - We decide to take a different approach, to move fraud prevention to a centralized location, the network. - This way, the user could easily protect themselves in one click by connecting to our WiFi gateway, removing the obstacle of installing and setting up their own systems. 
- Also, sysadmins can manage gateways from our central control portal, boosting maintainability.

## What it does
- An AI-powered gateway system that monitors visited websites and evaluates whether their content shows signs of financial fraud.
- Features:  Real-time website monitoring, AI-based content analysis, fraud signal detection, structured risk scoring.
- Users browse normally while the system runs in the background and provides clear warnings when a suspicious website is detected.
- If detected, the destination IP is blocked and subsequent requests to the same destination are intercepted. 
- The user are shown with a page presenting the reason for blocking. Providing an explainable, multi-dimensional fraud assessment instead of only blacklist-based checking.

## How we built it
- We first set up a Raspberry Pi 0 to act as a relay. We created a Go program to intercept incoming HTTP traffic and forward request forward. 
- Once we intercepted the return request, we read its TLS connection data and obtain the domain and HTML which is sent to an LLM to analyze. 
- Based on a detection score, suspicious domains are blocked and will return the "page blocked" page we built to the user.
- We also built a Go back-end to host a dashboard page to report statistics and manage blocked sites.

## Challenges we ran into
- Testing: It was challenging to find test sites that contained financial fraud, since they are either well-hidden or too obvious. 
- Client side rendered sites: Sites that does not return a populated HTML are hard to examine since the Pi had limited performance, making it hard to render the whole page on it.
- Ethics issues: Some may argue that it is unethical to use the private data contained in these requests. But we never retain any sensitive data and used ethical AI providers.

## Accomplishments that we're proud of
- Setting up the hardware: We spent some time setting up the Pi and a testing phone to route the network correctly. This involved learning a bit about networking and the relevant Go packages to solve the task.
- Optimizing the prompt to increase the detection accuracy

## What we learned
- Some networking principles
- Increased knowledge in Golang
- Prompt engineering
- Elevated awareness for scams in our search for test data

## What's next 
- Use a headless browser to render the page and increase accuracy.
- Optimize the solution for the cloud, as a distributed cloud system with a centralized controller node that manages all gateway nodes. 


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
GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 go build -o mitm .
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
