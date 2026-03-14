# Proxy Dashboard API Documentation

This document describes the mock API used by the dashboard pages. The responses are served as static JSON files under `public/api` in the frontend app.

## Base URL

- Development: `http://localhost:5173`
- Production: same origin as deployed frontend

## 1) Overview API

- Endpoint: `GET /api/overview.json`
- Used by: Overview page stat cards + approval breakdown

### Response

```json
{
  "traffic": { "value": "1.48 Gbps", "delta": "+6.2%" },
  "connections": { "value": "25,991", "delta": "+1,304" },
  "approved": { "value": "21,472", "delta": "85.9%" },
  "blocked": { "value": "3,509", "delta": "14.1%" }
}
```

### Notes

- `connections.value`, `approved.value`, and `blocked.value` are formatted strings and should be parsed before math.
- `pending` is computed on the client as:
  - `pending = connections - approved - blocked`

## 2) Traffic API

- Endpoint: `GET /api/traffic.json`
- Used by: Overview page traffic status table

### Response

```json
[
  { "time": "00:00", "inboundMbps": 410, "outboundMbps": 378 },
  { "time": "03:00", "inboundMbps": 368, "outboundMbps": 322 },
  { "time": "06:00", "inboundMbps": 452, "outboundMbps": 401 },
  { "time": "09:00", "inboundMbps": 639, "outboundMbps": 575 },
  { "time": "12:00", "inboundMbps": 721, "outboundMbps": 688 },
  { "time": "15:00", "inboundMbps": 684, "outboundMbps": 627 },
  { "time": "18:00", "inboundMbps": 596, "outboundMbps": 544 },
  { "time": "21:00", "inboundMbps": 474, "outboundMbps": 419 }
]
```

### Notes

- Each item represents one time slice.
- Client computes `total = inboundMbps + outboundMbps`.

## 3) Blocked Entries API

- Endpoint: `GET /api/blocked.json`
- Used by: Blocklist management page

### Response

```json
[
  {
    "id": "BLK-1092",
    "source": "10.8.12.41",
    "destination": "unknown-c2.example",
    "reason": "Known command-and-control domain pattern",
    "category": "Malware",
    "blockedAt": "2026-03-14 09:14:52",
    "hitCount": 41,
    "status": "active"
  }
]
```

### Notes

- `status` can be `active` or `review`.
- `category` can be `Malware`, `Policy`, `Bot`, or `DLP`.

## 4) Logs API

- Endpoint: `GET /api/logs.json`
- Used by: Logs page

### Response

```json
[
  {
    "id": 1,
    "timestamp": "2026-03-14 09:18:01.112",
    "level": "INFO",
    "source": "router.edge-a",
    "message": "Connection accepted from 10.8.12.41 via TLS1.3.",
    "requestId": "req-ae13d01"
  }
]
```

### Notes

- `level` can be `INFO`, `WARN`, or `ERROR`.
- Client supports level filter and free-text search.

## Frontend Request Map

- Overview page:
  - `GET /api/overview.json`
  - `GET /api/traffic.json`
- Blocklist page:
  - `GET /api/blocked.json`
- Logs page:
  - `GET /api/logs.json`
