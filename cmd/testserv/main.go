package main

import (
	"database/sql"
	"log"

	"github.com/C20H12/GenAI-Genesis-2026/serv"
	_ "modernc.org/sqlite"
)

func main() {
	db, err := sql.Open("sqlite", "fraud.db")
	if err != nil {
		log.Fatalf("open fraud.db: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		log.Fatalf("ping fraud.db: %v", err)
	}

	if err := ensureBlacklistSchema(db); err != nil {
		log.Fatalf("ensure blacklist schema: %v", err)
	}

	// if err := loadBlacklistFromFraud(db); err != nil {
	// 	log.Fatalf("load blacklist from fraud_results: %v", err)
	// }

	log.Println("blacklist table loaded from fraud_results")
	serv.StartServer(db)
}

func ensureBlacklistSchema(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS blacklist (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			domain     TEXT,
			score      INTEGER,
			reason     TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	return err
}

// func loadBlacklistFromFraud(db *sql.DB) error {
// 	tx, err := db.Begin()
// 	if err != nil {
// 		return err
// 	}
// 	defer func() {
// 		if err != nil {
// 			_ = tx.Rollback()
// 		}
// 	}()

// 	if _, err = tx.Exec(`DELETE FROM blacklist`); err != nil {
// 		return err
// 	}

// 	_, err = tx.Exec(`
// 		INSERT INTO blacklist (domain, score, reason, created_at)
// 		SELECT
// 			COALESCE(url, '') AS domain,
// 			MAX(score) AS score,
// 			MAX(reason) AS reason,
// 			MAX(created_at) AS created_at
// 		FROM fraud_results
// 		WHERE COALESCE(score, 0) >= 65
// 		  AND COALESCE(url, '') <> ''
// 		GROUP BY domain
// 		ORDER BY datetime(MAX(created_at)) DESC
// 	`)
// 	if err != nil {
// 		return err
// 	}

// 	return tx.Commit()
// }
