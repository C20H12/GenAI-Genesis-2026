package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"

	gopsutilnet "github.com/shirou/gopsutil/v4/net"

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
	Destination string `json:"destination"`
	Reason      string `json:"reason"`
	BlockedAt   string `json:"blockedAt"`
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
	db, err := sql.Open("sqlite", "file:fraud.db?_pragma=journal_mode(WAL)")
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
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS fraud_results (
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		url        TEXT,
		method     TEXT,
		score      INTEGER,
		reason     TEXT,
		client_ip  TEXT,
		remote_ip  TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	return err
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

	var totalEntries int
	err := s.db.QueryRow(`SELECT COUNT(1) FROM fraud_results`).Scan(&totalEntries)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	var approvedEntries int
	err = s.db.QueryRow(`SELECT COUNT(1) FROM fraud_results WHERE score < 65`).Scan(&approvedEntries)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	blockedEntries := maxInt(totalEntries-approvedEntries, 0)

	var createdLast24h int
	err = s.db.QueryRow(`
		SELECT COUNT(1)
		FROM fraud_results
		WHERE datetime(created_at) >= datetime('now', '-24 hours')
	`).Scan(&createdLast24h)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	trafficValue, trafficDelta := getSystemTrafficMetric()

	response := overviewResponse{
		Traffic: metric{
			Value: trafficValue,
			Delta: trafficDelta,
		},
		Connections: metric{
			Value: formatInt(totalEntries),
			Delta: fmt.Sprintf("+%s/24h", formatInt(createdLast24h)),
		},
		Approved: metric{
			Value: formatInt(approvedEntries),
			Delta: fmt.Sprintf("%.1f%%", ratioPercent(approvedEntries, totalEntries)),
		},
		Blocked: metric{
			Value: formatInt(blockedEntries),
			Delta: fmt.Sprintf("%.1f%%", ratioPercent(blockedEntries, totalEntries)),
		},
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

	rows, err := s.db.Query(`
		SELECT CAST(strftime('%H', created_at) AS INTEGER) AS hour_bucket, score
		FROM fraud_results
		WHERE datetime(created_at) >= datetime('now', '-24 hours')
	`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	defer rows.Close()

	buckets := []string{"00:00", "03:00", "06:00", "09:00", "12:00", "15:00", "18:00", "21:00"}
	points := make([]trafficPoint, len(buckets))
	for i, label := range buckets {
		points[i] = trafficPoint{Time: label}
	}

	for rows.Next() {
		var hour int
		var score int
		if err := rows.Scan(&hour, &score); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		idx := clampInt(hour/3, 0, len(points)-1)
		points[idx].InboundMbps += 12
		if score < 65 {
			points[idx].OutboundMbps += 12
		}
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
		SELECT id, domain, score, reason, created_at
		FROM blacklist
		ORDER BY datetime(created_at) DESC
	`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	defer rows.Close()


	entries := make([]blockedEntry, 0, 32)
	for rows.Next() {
		var rawID int
		var entry blockedEntry
		var score int
		if err := rows.Scan(
			&rawID,
			&entry.Destination,
			&score,
			&entry.Reason,
			&entry.BlockedAt,
		); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		entry.ID = fmt.Sprintf("FRD-%d", rawID)
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
	rowID, ok := parseBlockedID(id)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid blocked id"})
		return
	}

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
		`UPDATE blacklist SET domain = ?, reason = ? WHERE id = ?`,
		payload.Destination,
		payload.Reason,
		rowID,
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
	rowID, ok := parseBlockedID(id)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid blocked id"})
		return
	}

	result, err := s.db.Exec(`DELETE FROM blacklist WHERE id = ?`, rowID)
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

	rows, err := s.db.Query(`
		SELECT id, created_at, score, url, reason, client_ip
		FROM fraud_results
		ORDER BY id DESC
		LIMIT 500
	`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	defer rows.Close()

	logs := make([]proxyLog, 0, 64)
	for rows.Next() {
		var item proxyLog
		var score int
		var url string
		if err := rows.Scan(&item.ID, &item.Timestamp, &score, &url, &item.Message, &item.Source); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		item.Level = logLevel(score)
		item.RequestID = fmt.Sprintf("fraud-%d", item.ID)
		if item.Message == "" {
			item.Message = fmt.Sprintf("Scored URL %s", url)
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
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("encode json response: %v", err)
	}
}

func parseBlockedID(id string) (int, bool) {
	trimmed := strings.TrimSpace(id)
	trimmed = strings.TrimPrefix(trimmed, "FRD-")
	parsed, err := strconv.Atoi(trimmed)
	if err != nil || parsed <= 0 {
		return 0, false
	}
	return parsed, true
}

func logLevel(score int) string {
	if score >= 85 {
		return "BLOCKED"
	}
	if score >= 65 {
		return "WARN"
	}
	return "OK"
}

func getSystemTrafficMetric() (string, string) {
	counters, err := gopsutilnet.IOCounters(false)
	if err != nil || len(counters) == 0 {
		return "0 B", "system"
	}

	totalBytes := counters[0].BytesRecv + counters[0].BytesSent
	return humanBytes(totalBytes), "system"
}

func humanBytes(size uint64) string {
	units := []string{"B", "KB", "MB", "GB", "TB", "PB"}
	v := float64(size)
	idx := 0
	for v >= 1024 && idx < len(units)-1 {
		v /= 1024
		idx++
	}
	if idx == 0 {
		return fmt.Sprintf("%d %s", size, units[idx])
	}
	return fmt.Sprintf("%.2f %s", v, units[idx])
}

func ratioPercent(part, total int) float64 {
	if total <= 0 {
		return 0
	}
	v := (float64(part) / float64(total)) * 100
	return math.Round(v*10) / 10
}

func formatInt(n int) string {
	if n == 0 {
		return "0"
	}
	negative := n < 0
	if negative {
		n = -n
	}

	parts := make([]string, 0, 8)
	for n > 0 {
		chunk := n % 1000
		n /= 1000
		if n > 0 {
			parts = append(parts, fmt.Sprintf("%03d", chunk))
		} else {
			parts = append(parts, strconv.Itoa(chunk))
		}
	}

	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}

	value := strings.Join(parts, ",")
	if negative {
		return "-" + value
	}
	return value
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func clampInt(value, min, max int) int {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}
