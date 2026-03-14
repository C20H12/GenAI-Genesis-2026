# Proxy API Server (Go + SQLite)

Simple backend for the dashboard API documented in `front/API_DOCS.md`.

## Run

```powershell
go run main.go
```

Optional port override:

```powershell
$env:PORT="8080"
go run main.go
```

The server creates a SQLite database file `proxy.db` in this folder and auto-seeds data on first run.

## Endpoints

- `GET /health`
- `GET /api/overview.json`
- `GET /api/traffic.json`
- `GET /api/blocked.json`
- `GET /api/logs.json`
- `PATCH /api/blocked/{id}`
- `DELETE /api/blocked/{id}`

## Example PATCH

```powershell
curl -X PATCH http://localhost:8080/api/blocked/BLK-1092 \
  -H "Content-Type: application/json" \
  -d '{"destination":"new-target.example","reason":"Updated by admin"}'
```

## Example DELETE

```powershell
curl -X DELETE http://localhost:8080/api/blocked/BLK-1092
```
