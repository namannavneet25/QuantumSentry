// Package main — db.go
//
// This file implements the SQLite persistence layer for QuantumSentry.
// It stores scan results and an immutable audit trail for compliance.
//
// Tables:
//   - scans      : One row per completed scan (CBOM JSON + verdict)
//   - audit_log  : One row per API request (action, target, status, timestamp)
package main

import (
	"database/sql"
	"log"
	"time"

	_ "modernc.org/sqlite" // Pure-Go SQLite driver — no CGo/DLL required
)

// DB is the package-level database handle shared across all handlers.
var DB *sql.DB

// InitDB opens (or creates) the SQLite database file and runs migrations.
// The file is created in the working directory as quantumsentry.db.
func InitDB() {
	var err error
	DB, err = sql.Open("sqlite", "./quantumsentry.db")
	if err != nil {
		log.Fatal("Failed to open database:", err)
	}

	// Verify the connection is alive.
	if err = DB.Ping(); err != nil {
		log.Fatal("Failed to ping database:", err)
	}

	// Apply schema migrations (idempotent — safe to run every startup).
	runMigrations()
	log.Println("Database initialised: quantumsentry.db")
}

// runMigrations creates tables if they do not already exist.
func runMigrations() {
	schema := `
	-- Stores one completed scan result per row.
	CREATE TABLE IF NOT EXISTS scans (
		id          TEXT    PRIMARY KEY,   -- scan_id from CBOM (e.g. "google.com:443-1711623001")
		timestamp   TEXT    NOT NULL,      -- ISO-8601 scan timestamp
		target      TEXT    NOT NULL,      -- host:port that was scanned
		verdict     TEXT    NOT NULL,      -- "safe" | "hybrid" | "vuln"
		verdict_label TEXT  NOT NULL,      -- human-readable label
		tls_version TEXT    NOT NULL DEFAULT '',
		selected_group TEXT NOT NULL DEFAULT '',
		cbom_json   TEXT    NOT NULL       -- full CBOM JSON blob
	);

	-- Immutable audit trail for all API actions.
	CREATE TABLE IF NOT EXISTS audit_log (
		id        INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp TEXT    NOT NULL,        -- ISO-8601
		action    TEXT    NOT NULL,        -- "SCAN" | "GET_HISTORY" | etc.
		target    TEXT    NOT NULL DEFAULT '',
		status    TEXT    NOT NULL,        -- "OK" | "ERROR"
		detail    TEXT    NOT NULL DEFAULT '' -- error message or extra context
	);`

	if _, err := DB.Exec(schema); err != nil {
		log.Fatal("Migration failed:", err)
	}
}

// ── Scan operations ──────────────────────────────────────────────────────────

// ScanRecord is a single row from the scans table.
type ScanRecord struct {
	ID            string `json:"id"`
	Timestamp     string `json:"timestamp"`
	Target        string `json:"target"`
	Verdict       string `json:"verdict"`
	VerdictLabel  string `json:"verdict_label"`
	TLSVersion    string `json:"tls_version"`
	SelectedGroup string `json:"selected_group"`
	CBOMJson      string `json:"cbom_json,omitempty"` // omitted in list views
}

// SaveScan persists a completed scan result.
// If a scan with the same ID already exists it is replaced (upsert).
func SaveScan(r ScanRecord) error {
	_, err := DB.Exec(`
		INSERT OR REPLACE INTO scans
			(id, timestamp, target, verdict, verdict_label, tls_version, selected_group, cbom_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.Timestamp, r.Target,
		r.Verdict, r.VerdictLabel,
		r.TLSVersion, r.SelectedGroup,
		r.CBOMJson,
	)
	return err
}

// GetHistory returns the last `limit` scans ordered newest-first.
// The cbom_json column is intentionally excluded for list performance.
func GetHistory(limit int) ([]ScanRecord, error) {
	rows, err := DB.Query(`
		SELECT id, timestamp, target, verdict, verdict_label, tls_version, selected_group
		FROM scans
		ORDER BY timestamp DESC
		LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []ScanRecord
	for rows.Next() {
		var r ScanRecord
		if err := rows.Scan(
			&r.ID, &r.Timestamp, &r.Target,
			&r.Verdict, &r.VerdictLabel,
			&r.TLSVersion, &r.SelectedGroup,
		); err != nil {
			return nil, err
		}
		records = append(records, r)
	}
	return records, rows.Err()
}

// GetScanByID returns the full CBOM JSON for a specific scan ID.
func GetScanByID(id string) (*ScanRecord, error) {
	row := DB.QueryRow(`
		SELECT id, timestamp, target, verdict, verdict_label, tls_version, selected_group, cbom_json
		FROM scans WHERE id = ?`, id)

	var r ScanRecord
	err := row.Scan(
		&r.ID, &r.Timestamp, &r.Target,
		&r.Verdict, &r.VerdictLabel,
		&r.TLSVersion, &r.SelectedGroup,
		&r.CBOMJson,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &r, err
}

// ── Audit log operations ─────────────────────────────────────────────────────

// AuditRecord is a single row from the audit_log table.
type AuditRecord struct {
	ID        int64  `json:"id"`
	Timestamp string `json:"timestamp"`
	Action    string `json:"action"`
	Target    string `json:"target"`
	Status    string `json:"status"`
	Detail    string `json:"detail,omitempty"`
}

// LogAudit appends a record to the audit trail.
func LogAudit(action, target, status, detail string) {
	_, err := DB.Exec(`
		INSERT INTO audit_log (timestamp, action, target, status, detail)
		VALUES (?, ?, ?, ?, ?)`,
		time.Now().UTC().Format(time.RFC3339),
		action, target, status, detail,
	)
	if err != nil {
		log.Println("Audit log write failed:", err)
	}
}

// GetAuditLog returns the last `limit` audit entries ordered newest-first.
func GetAuditLog(limit int) ([]AuditRecord, error) {
	rows, err := DB.Query(`
		SELECT id, timestamp, action, target, status, detail
		FROM audit_log
		ORDER BY id DESC
		LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []AuditRecord
	for rows.Next() {
		var r AuditRecord
		if err := rows.Scan(&r.ID, &r.Timestamp, &r.Action, &r.Target, &r.Status, &r.Detail); err != nil {
			return nil, err
		}
		records = append(records, r)
	}
	return records, rows.Err()
}
