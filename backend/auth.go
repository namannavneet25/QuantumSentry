// Package main — auth.go
//
// Implements JWT-based authentication and Role-Based Access Control (RBAC)
// for the QuantumSentry backend.
//
// Roles:
//   admin   — full access: scan, bulk scan, view history, view audit, manage users
//   auditor — read-only: view history, view audit (cannot trigger scans)
//   viewer  — scan only: can run scans, see results (cannot see audit trail)
//
// Default credentials (change in production):
//   admin   / QuantumSentry@Admin2026
//   auditor / QuantumSentry@Audit2026
//   viewer  / QuantumSentry@View2026
//
// Token TTL: 24 hours. Stored in browser localStorage as "qs_token".
package main

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// jwtSecret is the signing key for JWT tokens.
// In production this should be loaded from an environment variable.
var jwtSecret = []byte("qs-pqc-secret-2026-change-in-prod")

// ── User model ────────────────────────────────────────────────────────────────

// User represents a QuantumSentry dashboard user.
type User struct {
	ID           int64  `json:"id"`
	Username     string `json:"username"`
	Role         string `json:"role"`           // "admin" | "auditor" | "viewer"
	PasswordHash string `json:"-"`              // never serialised to JSON
}

// ── DB helpers ────────────────────────────────────────────────────────────────

// initUsersTable creates the users table and seeds default accounts.
func initUsersTable() {
	_, _ = DB.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			username      TEXT    NOT NULL UNIQUE,
			password_hash TEXT    NOT NULL,
			role          TEXT    NOT NULL DEFAULT 'viewer'
		)`)

	seeds := []struct{ u, p, r string }{
		{"admin",   "QuantumSentry@Admin2026", "admin"},
		{"auditor", "QuantumSentry@Audit2026", "auditor"},
		{"viewer",  "QuantumSentry@View2026",  "viewer"},
	}
	for _, s := range seeds {
		var count int
		_ = DB.QueryRow(`SELECT COUNT(*) FROM users WHERE username = ?`, s.u).Scan(&count)
		if count == 0 {
			hash, _ := bcrypt.GenerateFromPassword([]byte(s.p), bcrypt.DefaultCost)
			_, _ = DB.Exec(`INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)`,
				s.u, string(hash), s.r)
		}
	}
}

// findUserByUsername looks up a user record from the DB.
func findUserByUsername(username string) (*User, error) {
	row := DB.QueryRow(`SELECT id, username, password_hash, role FROM users WHERE username = ?`, username)
	var u User
	if err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role); err != nil {
		return nil, err
	}
	return &u, nil
}

// ── JWT helpers ───────────────────────────────────────────────────────────────

// Claims is the JWT payload.
type Claims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

// generateToken mints a signed JWT for the given user (TTL: 24 h).
func generateToken(u *User) (string, error) {
	claims := Claims{
		Username: u.Username,
		Role:     u.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   u.Username,
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(jwtSecret)
}

// parseToken validates a JWT string and returns the Claims.
func parseToken(tokenStr string) (*Claims, error) {
	t, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !t.Valid {
		return nil, err
	}
	return t.Claims.(*Claims), nil
}

// ── Handlers ─────────────────────────────────────────────────────────────────

// LoginRequest is the JSON body for POST /auth/login.
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// handleLogin validates credentials and returns a JWT.
func handleLogin(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username and password required"})
		return
	}

	user, err := findUserByUsername(strings.TrimSpace(req.Username))
	if err != nil {
		LogAudit("LOGIN", req.Username, "ERROR", "user not found")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		LogAudit("LOGIN", req.Username, "ERROR", "wrong password")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	token, err := generateToken(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token generation failed"})
		return
	}

	LogAudit("LOGIN", req.Username, "OK", "role="+user.Role)
	c.JSON(http.StatusOK, gin.H{
		"token":    token,
		"username": user.Username,
		"role":     user.Role,
	})
}

// handleMe returns the current user's info from the JWT (no DB hit).
func handleMe(c *gin.Context) {
	claims, _ := c.Get("claims")
	cl := claims.(*Claims)
	c.JSON(http.StatusOK, gin.H{
		"username": cl.Username,
		"role":     cl.Role,
	})
}

// ── Middleware ────────────────────────────────────────────────────────────────

// AuthMiddleware validates the Bearer token and injects claims into the context.
// Returns 401 if the token is missing or invalid.
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
			return
		}
		claims, err := parseToken(strings.TrimPrefix(auth, "Bearer "))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
			return
		}
		c.Set("claims", claims)
		c.Next()
	}
}

// RequireRole returns a middleware that allows only the specified roles.
// Must be used after AuthMiddleware.
func RequireRole(roles ...string) gin.HandlerFunc {
	allowed := map[string]bool{}
	for _, r := range roles {
		allowed[r] = true
	}
	return func(c *gin.Context) {
		claims, _ := c.Get("claims")
		cl := claims.(*Claims)
		if !allowed[cl.Role] {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "your role (" + cl.Role + ") does not have permission for this action",
			})
			return
		}
		c.Next()
	}
}
