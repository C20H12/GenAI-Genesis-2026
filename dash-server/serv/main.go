package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	_ "modernc.org/sqlite"
)

type metric struct {
	Value string `json:"value"`
	Delta string `json:"delta"`
}

type overviewResponse struct {
	Traffic     metric `json:"traffic"`
	Connections metric `json:"connections"`
	Approved    metric `json:"approved"`
	Blocked     metric `json:"blocked"`
}

type trafficPoint struct {
	Time         string `json:"time"`
	InboundMbps  int    `json:"inboundMbps"`
	OutboundMbps int    `json:"outboundMbps"`
}

type blockedEntry struct {
	ID          string `json:"id"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Reason      string `json:"reason"`
	Category    string `json:"category"`
	BlockedAt   string `json:"blockedAt"`
	HitCount    int    `json:"hitCount"`
	Status      string `json:"status"`
}

type proxyLog struct {
	ID        int    `json:"id"`
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Source    string `json:"source"`
	Message   string `json:"message"`
	RequestID string `json:"requestId"`
}

type updateBlockedRequest struct {
	Destination string `json:"destination"`
	Reason      string `json:"reason"`
}

type server struct {
	db *sql.DB
}

func main() {
	db, err := sql.Open("sqlite", "file:proxy.db?_pragma=journal_mode(WAL)")
	if err != nil {
		log.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()

	if err := initSchema(db); err != nil {
		log.Fatalf("init schema: %v", err)
	}

	// if err := seedData(db); err != nil {
	// 	log.Fatalf("seed data: %v", err)
	// }

	s := &server{db: db}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/overview.json", s.handleOverview)
	mux.HandleFunc("/api/traffic.json", s.handleTraffic)
	mux.HandleFunc("/api/blocked.json", s.handleBlockedList)
	mux.HandleFunc("/api/logs.json", s.handleLogs)
	mux.HandleFunc("/api/blocked/", s.handleBlockedByID)
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "6767"
	}

	addr := ":" + port
	log.Printf("proxy API listening on %s", addr)
	if err := http.ListenAndServe(addr, withCORS(mux)); err != nil {
		log.Fatal(err)
	}
}

func initSchema(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS overview_metrics (
			name TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			delta TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS traffic_series (
			time TEXT PRIMARY KEY,
			inbound_mbps INTEGER NOT NULL,
			outbound_mbps INTEGER NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS blocked_entries (
			id TEXT PRIMARY KEY,
			source TEXT NOT NULL,
			destination TEXT NOT NULL,
			reason TEXT NOT NULL,
			category TEXT NOT NULL,
			blocked_at TEXT NOT NULL,
			hit_count INTEGER NOT NULL,
			status TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS proxy_logs (
			id INTEGER PRIMARY KEY,
			timestamp TEXT NOT NULL,
			level TEXT NOT NULL,
			source TEXT NOT NULL,
			message TEXT NOT NULL,
			request_id TEXT NOT NULL
		);`,
	}

	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

// func seedData(db *sql.DB) error {
// 	if err := seedOverview(db); err != nil {
// 		return err
// 	}
// 	if err := seedTraffic(db); err != nil {
// 		return err
// 	}
// 	if err := seedBlocked(db); err != nil {
// 		return err
// 	}
// 	if err := seedLogs(db); err != nil {
// 		return err
// 	}
// 	return nil
// }

// func seedOverview(db *sql.DB) error {
// 	count, err := tableCount(db, "overview_metrics")
// 	if err != nil {
// 		return err
// 	}
// 	if count > 0 {
// 		return nil
// 	}

// 	rows := []struct {
// 		Name  string
// 		Value string
// 		Delta string
// 	}{
// 		{"traffic", "1.48 Gbps", "+6.2%"},
// 		{"connections", "25,991", "+1,304"},
// 		{"approved", "21,472", "85.9%"},
// 		{"blocked", "3,509", "14.1%"},
// 	}

// 	for _, row := range rows {
// 		_, err := db.Exec(`INSERT INTO overview_metrics(name, value, delta) VALUES(?, ?, ?)`, row.Name, row.Value, row.Delta)
// 		if err != nil {
// 			return err
// 		}
// 	}
// 	return nil
// }

// func seedTraffic(db *sql.DB) error {
// 	count, err := tableCount(db, "traffic_series")
// 	if err != nil {
// 		return err
// 	}
// 	if count > 0 {
// 		return nil
// 	}

// 	rows := []trafficPoint{
// 		{Time: "00:00", InboundMbps: 410, OutboundMbps: 378},
// 		{Time: "03:00", InboundMbps: 368, OutboundMbps: 322},
// 		{Time: "06:00", InboundMbps: 452, OutboundMbps: 401},
// 		{Time: "09:00", InboundMbps: 639, OutboundMbps: 575},
// 		{Time: "12:00", InboundMbps: 721, OutboundMbps: 688},
// 		{Time: "15:00", InboundMbps: 684, OutboundMbps: 627},
// 		{Time: "18:00", InboundMbps: 596, OutboundMbps: 544},
// 		{Time: "21:00", InboundMbps: 474, OutboundMbps: 419},
// 	}

// 	for _, row := range rows {
// 		_, err := db.Exec(`INSERT INTO traffic_series(time, inbound_mbps, outbound_mbps) VALUES(?, ?, ?)`, row.Time, row.InboundMbps, row.OutboundMbps)
// 		if err != nil {
// 			return err
// 		}
// 	}
// 	return nil
// }

// func seedBlocked(db *sql.DB) error {
// 	count, err := tableCount(db, "blocked_entries")
// 	if err != nil {
// 		return err
// 	}
// 	if count > 0 {
// 		return nil
// 	}

// 	rows := []blockedEntry{
// 		{ID: "BLK-1092", Source: "10.8.12.41", Destination: "unknown-c2.example", Reason: "Known command-and-control domain pattern", Category: "Malware", BlockedAt: "2026-03-14 09:14:52", HitCount: 41, Status: "active"},
// 		{ID: "BLK-1093", Source: "10.8.15.201", Destination: "social-feed.example", Reason: "Domain blocked by work-hours policy", Category: "Policy", BlockedAt: "2026-03-14 09:15:10", HitCount: 5, Status: "review"},
// 		{ID: "BLK-1094", Source: "10.8.2.29", Destination: "api-scrape.target.example", Reason: "Automated request burst exceeded threshold", Category: "Bot", BlockedAt: "2026-03-14 09:16:43", HitCount: 116, Status: "active"},
// 		{ID: "BLK-1095", Source: "10.8.44.8", Destination: "paste.share.example", Reason: "Potential sensitive payload signature detected", Category: "DLP", BlockedAt: "2026-03-14 09:17:08", HitCount: 12, Status: "active"},
// 	}

// 	for _, row := range rows {
// 		_, err := db.Exec(
// 			`INSERT INTO blocked_entries(id, source, destination, reason, category, blocked_at, hit_count, status) VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
// 			row.ID,
// 			row.Source,
// 			row.Destination,
// 			row.Reason,
// 			row.Category,
// 			row.BlockedAt,
// 			row.HitCount,
// 			row.Status,
// 		)
// 		if err != nil {
// 			return err
// 		}
// 	}
// 	return nil
// }

// func seedLogs(db *sql.DB) error {
// 	count, err := tableCount(db, "proxy_logs")
// 	if err != nil {
// 		return err
// 	}
// 	if count > 0 {
// 		return nil
// 	}

// 	rows := []proxyLog{
// 		{ID: 1, Timestamp: "2026-03-14 09:18:01.112", Level: "INFO", Source: "router.edge-a", Message: "Connection accepted from 10.8.12.41 via TLS1.3.", RequestID: "req-ae13d01"},
// 		{ID: 2, Timestamp: "2026-03-14 09:18:02.403", Level: "WARN", Source: "filter.policy", Message: "Blocked request to social-feed.example by policy rule P-44.", RequestID: "req-ae13d39"},
// 		{ID: 3, Timestamp: "2026-03-14 09:18:04.220", Level: "ERROR", Source: "upstream.gateway", Message: "Upstream timeout after 8000ms to api.partners.example.", RequestID: "req-ae13d62"},
// 		{ID: 4, Timestamp: "2026-03-14 09:18:05.904", Level: "INFO", Source: "telemetry.agent", Message: "Metrics batch flushed. samples=256 lag=18ms.", RequestID: "req-ae13da0"},
// 		{ID: 5, Timestamp: "2026-03-14 09:18:06.711", Level: "WARN", Source: "throttle.guard", Message: "Rate limit triggered for 10.8.2.29; window=60s.", RequestID: "req-ae13dd4"},
// 	}

// 	for _, row := range rows {
// 		_, err := db.Exec(
// 			`INSERT INTO proxy_logs(id, timestamp, level, source, message, request_id) VALUES(?, ?, ?, ?, ?, ?)`,
// 			row.ID,
// 			row.Timestamp,
// 			row.Level,
// 			row.Source,
// 			row.Message,
// 			row.RequestID,
// 		)
// 		if err != nil {
// 			return err
// 		}
// 	}
// 	return nil
// }

func tableCount(db *sql.DB, table string) (int, error) {
	query := fmt.Sprintf("SELECT COUNT(1) FROM %s", table)
	var count int
	if err := db.QueryRow(query).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func (s *server) handleOverview(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w, r.Method, http.MethodGet)
		return
	}

	rows, err := s.db.Query(`SELECT name, value, delta FROM overview_metrics`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	defer rows.Close()

	response := overviewResponse{}
	for rows.Next() {
		var name string
		var value string
		var delta string
		if err := rows.Scan(&name, &value, &delta); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		item := metric{Value: value, Delta: delta}
		switch name {
		case "traffic":
			response.Traffic = item
		case "connections":
			response.Connections = item
		case "approved":
			response.Approved = item
		case "blocked":
			response.Blocked = item
		}
	}

	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusOK, response)
}

func (s *server) handleTraffic(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w, r.Method, http.MethodGet)
		return
	}

	rows, err := s.db.Query(`SELECT time, inbound_mbps, outbound_mbps FROM traffic_series ORDER BY time`) // time is HH:mm
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	defer rows.Close()

	points := make([]trafficPoint, 0, 16)
	for rows.Next() {
		var p trafficPoint
		if err := rows.Scan(&p.Time, &p.InboundMbps, &p.OutboundMbps); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		points = append(points, p)
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusOK, points)
}

func (s *server) handleBlockedList(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w, r.Method, http.MethodGet)
		return
	}

	rows, err := s.db.Query(`
		SELECT id, source, destination, reason, category, blocked_at, hit_count, status
		FROM blocked_entries
		ORDER BY blocked_at DESC
	`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	defer rows.Close()

	entries := make([]blockedEntry, 0, 32)
	for rows.Next() {
		var entry blockedEntry
		if err := rows.Scan(
			&entry.ID,
			&entry.Source,
			&entry.Destination,
			&entry.Reason,
			&entry.Category,
			&entry.BlockedAt,
			&entry.HitCount,
			&entry.Status,
		); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusOK, entries)
}

func (s *server) handleBlockedByID(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/api/blocked/")
	if id == "" || strings.Contains(id, "/") {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}

	switch r.Method {
	case http.MethodPatch:
		s.handleBlockedPatch(w, r, id)
	case http.MethodDelete:
		s.handleBlockedDelete(w, r, id)
	default:
		methodNotAllowed(w, r.Method, http.MethodPatch, http.MethodDelete)
	}
}

func (s *server) handleBlockedPatch(w http.ResponseWriter, r *http.Request, id string) {
	var payload updateBlockedRequest
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}

	payload.Destination = strings.TrimSpace(payload.Destination)
	payload.Reason = strings.TrimSpace(payload.Reason)
	if payload.Destination == "" || payload.Reason == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "destination and reason are required"})
		return
	}

	result, err := s.db.Exec(
		`UPDATE blocked_entries SET destination = ?, reason = ? WHERE id = ?`,
		payload.Destination,
		payload.Reason,
		id,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if rowsAffected == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "entry not found"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (s *server) handleBlockedDelete(w http.ResponseWriter, _ *http.Request, id string) {
	result, err := s.db.Exec(`DELETE FROM blocked_entries WHERE id = ?`, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if rowsAffected == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "entry not found"})
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *server) handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w, r.Method, http.MethodGet)
		return
	}

	rows, err := s.db.Query(`SELECT id, timestamp, level, source, message, request_id FROM proxy_logs ORDER BY id`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	defer rows.Close()

	logs := make([]proxyLog, 0, 64)
	for rows.Next() {
		var item proxyLog
		if err := rows.Scan(&item.ID, &item.Timestamp, &item.Level, &item.Source, &item.Message, &item.RequestID); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		logs = append(logs, item)
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusOK, logs)
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func methodNotAllowed(w http.ResponseWriter, got string, allowed ...string) {
	w.Header().Set("Allow", strings.Join(allowed, ", "))
	writeJSON(w, http.StatusMethodNotAllowed, map[string]string{
		"error": fmt.Sprintf("method %s not allowed", got),
	})
}

func writeError(w http.ResponseWriter, status int, err error) {
	msg := "internal server error"
	if status >= 400 && status < 500 {
		msg = err.Error()
	}
	var sqErr interface{ Error() string }
	if errors.As(err, &sqErr) {
		_ = sqErr
	}
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("encode json response: %v", err)
	}
}
