// Package main implements the QuantumSentry backend API server.
//
// It serves the frontend dashboard as static files and exposes a JWT-protected
// REST API for PQC scanning, history retrieval, and compliance audit logging.
//
// Startup sequence:
//  1. InitDB() — open/create quantumsentry.db and run schema migrations
//  2. initUsersTable() — seed default admin/auditor/viewer accounts
//  3. Register Gin routes (public auth routes + protected API routes)
//  4. Listen on :8080
//
// Directory layout expected at runtime:
//
//	backend/          ← cwd when running server.exe
//	  server.exe
//	  quantumsentry.db  (created automatically)
//	../scanner/
//	  scanner.exe     ← invoked as subprocess per scan
//	../frontend/
//	  index.html · script.js · style.css
package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os/exec"
	"strings"
	"sync"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	InitDB()
	initUsersTable() // seed default admin/auditor/viewer accounts

	r := gin.Default()
	r.Use(cors.Default())

	// ── Audit middleware ───────────────────────────────────────────────────
	r.Use(func(c *gin.Context) {
		c.Next()
		path := c.Request.URL.Path
		if strings.HasPrefix(path, "/scan") ||
			strings.HasPrefix(path, "/history") ||
			strings.HasPrefix(path, "/audit") {
			status := "OK"
			if c.Writer.Status() >= 400 {
				status = "ERROR"
			}
			target := c.Query("target")
			if target == "" {
				target = c.Param("id")
			}
			LogAudit(strings.ToUpper(strings.TrimPrefix(path, "/")), target, status, "")
		}
	})

	// ── Static files ───────────────────────────────────────────────────────
	r.GET("/", func(c *gin.Context) { c.File("../frontend/index.html") })
	r.GET("/script.js", func(c *gin.Context) { c.File("../frontend/script.js") })
	r.GET("/style.css", func(c *gin.Context) { c.File("../frontend/style.css") })

	// ── Auth routes (public) ───────────────────────────────────────────────
	r.POST("/auth/login", handleLogin)
	r.GET("/auth/me", AuthMiddleware(), handleMe)

	// ── Protected routes ──────────────────────────────────────────────────
	protected := r.Group("/", AuthMiddleware())
	{
	// ── GET /scan?target=<host:port> ──────────────────────────────────────
	protected.GET("/scan", RequireRole("admin", "viewer"), func(c *gin.Context) {
		target := c.Query("target")
		if target == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "target query param required"})
			return
		}
		cbomBytes, err := runScan(target)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		persistScan(target, cbomBytes)
		c.Data(http.StatusOK, "application/json", cbomBytes)
	})

	// ── POST /scan/bulk ────────────────────────────────────────────────────
	// Body: { "targets": ["google.com:443", "cloudflare.com:443", ...] }
	// Runs up to 3 scans concurrently; returns array of CBOM results.
	r.POST("/scan/bulk", func(c *gin.Context) {
		var req struct {
			Targets []string `json:"targets"`
		}
		if err := c.ShouldBindJSON(&req); err != nil || len(req.Targets) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "body must be {\"targets\":[\"host:port\",...]}"})
			return
		}

		// Deduplicate and cap at 20 targets per request
		seen := map[string]bool{}
		var targets []string
		for _, t := range req.Targets {
			t = strings.TrimSpace(t)
			if t == "" || seen[t] {
				continue
			}
			seen[t] = true
			targets = append(targets, t)
			if len(targets) >= 20 {
				break
			}
		}

		type Result struct {
			Target string          `json:"target"`
			Status string          `json:"status"` // "ok" | "error"
			Error  string          `json:"error,omitempty"`
			CBOM   json.RawMessage `json:"cbom,omitempty"`
		}

		results := make([]Result, len(targets))

		// Semaphore to cap concurrency at 3 simultaneous scans
		sem := make(chan struct{}, 3)
		var wg sync.WaitGroup

		for i, target := range targets {
			wg.Add(1)
			go func(idx int, tgt string) {
				defer wg.Done()
				sem <- struct{}{}        // acquire
				defer func() { <-sem }() // release

				cbomBytes, err := runScan(tgt)
				if err != nil {
					results[idx] = Result{Target: tgt, Status: "error", Error: err.Error()}
					return
				}
				persistScan(tgt, cbomBytes)
				results[idx] = Result{Target: tgt, Status: "ok", CBOM: json.RawMessage(cbomBytes)}
			}(i, target)
		}

		wg.Wait()
		c.JSON(http.StatusOK, gin.H{
			"total":   len(targets),
			"results": results,
		})
	})

	// ── GET /history ─────────────────────────────────────────────────────
	protected.GET("/history", RequireRole("admin", "auditor"), func(c *gin.Context) {
		records, err := GetHistory(50)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if records == nil {
			records = []ScanRecord{}
		}
		c.JSON(http.StatusOK, gin.H{"scans": records})
	})

	// ── GET /history/:id ─────────────────────────────────────────────────
	protected.GET("/history/:id", RequireRole("admin", "auditor"), func(c *gin.Context) {
		rec, err := GetScanByID(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if rec == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
			return
		}
		c.Data(http.StatusOK, "application/json", []byte(rec.CBOMJson))
	})

	// ── GET /audit ───────────────────────────────────────────────────────
	protected.GET("/audit", RequireRole("admin", "auditor"), func(c *gin.Context) {
		entries, err := GetAuditLog(200)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if entries == nil {
			entries = []AuditRecord{}
		}
		c.JSON(http.StatusOK, gin.H{"entries": entries})
	})
	} // end protected group

	r.Run(":8080")
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// runScan invokes the scanner binary for a single target and returns its CBOM JSON.
func runScan(target string) ([]byte, error) {
	cmd := exec.Command("../scanner/scanner.exe", target)
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// cbomMeta is the minimal CBOM shape needed for DB persistence.
type cbomMeta struct {
	ScanID    string `json:"scan_id"`
	Timestamp string `json:"timestamp"`
	Assets    []struct {
		Protocols []struct {
			Version       string `json:"version"`
			SelectedGroup string `json:"selected_group"`
		} `json:"protocols"`
	} `json:"assets"`
}

// persistScan parses the CBOM bytes and saves a record to SQLite.
func persistScan(target string, cbomBytes []byte) {
	var meta cbomMeta
	if err := json.Unmarshal(cbomBytes, &meta); err != nil || meta.ScanID == "" {
		return
	}
	verdict, label := verdictFromMeta(meta)
	_ = SaveScan(ScanRecord{
		ID:            meta.ScanID,
		Timestamp:     meta.Timestamp,
		Target:        target,
		Verdict:       verdict,
		VerdictLabel:  label,
		TLSVersion:    safeGet(meta.Assets, 0),
		SelectedGroup: safeGetGroup(meta.Assets, 0),
		CBOMJson:      string(cbomBytes),
	})
}

// verdictFromMeta determines the PQC verdict from minimal CBOM metadata.
func verdictFromMeta(meta cbomMeta) (string, string) {
	if len(meta.Assets) == 0 || len(meta.Assets[0].Protocols) == 0 {
		return "unknown", "Unknown"
	}
	group := meta.Assets[0].Protocols[0].SelectedGroup
	purePQ := []string{"MLKEM512", "MLKEM768", "MLKEM1024"}
	hybrid  := []string{"X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024"}
	for _, g := range purePQ {
		if group == g { return "safe", "Post-Quantum Safe" }
	}
	for _, g := range hybrid {
		if group == g { return "hybrid", "Hybrid PQ — Partially Safe" }
	}
	return "vuln", "Quantum Vulnerable"
}

// safeGet returns the TLS version from the first protocol of the nth asset.
// Returns an empty string if the index is out of bounds.
func safeGet(assets []struct {
	Protocols []struct {
		Version       string `json:"version"`
		SelectedGroup string `json:"selected_group"`
	} `json:"protocols"`
}, idx int) string {
	if len(assets) > idx && len(assets[idx].Protocols) > 0 {
		return assets[idx].Protocols[0].Version
	}
	return ""
}

// safeGetGroup returns the selected KEM group from the first protocol of the nth asset.
// Returns an empty string if the index is out of bounds.
func safeGetGroup(assets []struct {
	Protocols []struct {
		Version       string `json:"version"`
		SelectedGroup string `json:"selected_group"`
	} `json:"protocols"`
}, idx int) string {
	if len(assets) > idx && len(assets[idx].Protocols) > 0 {
		return assets[idx].Protocols[0].SelectedGroup
	}
	return ""
}