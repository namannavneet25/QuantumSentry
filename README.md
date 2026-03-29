<div align="center">

<img src="https://img.shields.io/badge/Go-1.22+-00ADD8?style=for-the-badge&logo=go" />
<img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" />
<img src="https://img.shields.io/badge/TLS-1.3-blueviolet?style=for-the-badge" />
<img src="https://img.shields.io/badge/PQC-ML--KEM%20Ready-success?style=for-the-badge" />
<img src="https://img.shields.io/badge/CERT--In-CBOM%20Compliant-orange?style=for-the-badge" />

# ⚛ QuantumSentry

**Post-Quantum Cryptography (PQC) Readiness Scanner**

_Scan any HTTPS endpoint for quantum vulnerability. Generates audit-ready CBOM reports compliant with CERT-In SRS Annexure A._

</div>

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Build Instructions](#build-instructions)
- [Default Credentials](#default-credentials)
- [API Reference](#api-reference)
- [CBOM Schema](#cbom-schema)
- [Role-Based Access Control](#role-based-access-control)
- [Project Structure](#project-structure)
- [Troubleshooting](#troubleshooting)

---

## Overview

QuantumSentry is a network-level TLS inspection tool built for the **PSB Cybersecurity Hackathon 2026**. It captures live TLS handshakes using raw packet capture (Npcap/libpcap), extracts cryptographic parameters, and generates a **Cryptographic Bill of Materials (CBOM)** fully compliant with CERT-In's SRS Annexure A specification.

The dashboard allows teams to:
- Assess whether an endpoint uses quantum-safe key exchange (ML-KEM, X25519MLKEM768)
- Get actionable remediation recommendations with config commands
- Track scan history over time in a SQLite database
- Maintain an immutable audit trail for compliance
- Run bulk scans across multiple targets concurrently
- Export results as JSON or PDF "Quantum Safety Certificates"

---

## Features

| Feature | Description |
|---|---|
| 🔍 **Live TLS Inspection** | Raw packet capture via Npcap, extracts KEM groups, cipher suites, TLS version |
| 📋 **CBOM Generation** | Full Cryptographic Bill of Materials — algorithms, protocols, certificates, keys |
| 🏛️ **Annexure A Compliant** | `asset_type`, OIDs, key lifecycle, certificate format — all per CERT-In schema |
| 🟢🟡🔴 **PQC Verdict Engine** | Classifies endpoints as Post-Quantum Safe / Hybrid PQ / Quantum Vulnerable |
| 🔧 **Recommendations** | Severity-coded actionable remediation steps with exact config commands |
| 📥 **Export** | Download CBOM as JSON or generate a PDF "Quantum Safety Certificate" |
| ⚡ **Bulk Scanning** | Scan up to 20 targets concurrently (3 at a time), with CSV/TXT upload |
| 🕑 **Scan History** | SQLite-backed persistent history, click any row to reload past results |
| 📋 **Audit Trail** | Every API action logged automatically; viewable/exportable as CSV |
| 🔐 **JWT Authentication** | Bcrypt-hashed passwords, HS256 JWT tokens, 24-hour TTL |
| 👥 **RBAC** | 3 roles — Admin, Auditor, Viewer — each with controlled endpoint access |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Browser / Frontend                       │
│          index.html · script.js · style.css (Vanilla JS)        │
└───────────────────────────┬─────────────────────────────────────┘
                            │ HTTP (localhost:8080)
                            │ Authorization: Bearer <JWT>
┌───────────────────────────▼─────────────────────────────────────┐
│                     Backend (Go / Gin)                          │
│  main.go · auth.go · db.go                                      │
│  REST API:  /auth/login  /scan  /scan/bulk                      │
│             /history     /audit                                  │
│  SQLite DB: scans · audit_log · users                           │
└───────────────────────────┬─────────────────────────────────────┘
                            │ subprocess exec
┌───────────────────────────▼─────────────────────────────────────┐
│                     Scanner (Go / Npcap)                        │
│  main.go                                                        │
│  cbom/  →  types.go · algorithms.go · builder.go · utils.go    │
│  Raw TLS handshake capture → CBOM JSON output (stdout)          │
└─────────────────────────────────────────────────────────────────┘
```

**Data flow — single scan:**
1. Frontend sends `GET /scan?target=google.com:443` with Bearer token
2. Backend validates JWT → invokes `scanner.exe google.com:443`
3. Scanner dials TLS + captures raw packets → prints CBOM JSON to stdout
4. Backend parses CBOM, computes PQC verdict, persists to SQLite
5. Raw CBOM JSON returned to frontend → dashboard renders results

---

## Prerequisites

| Dependency | Version | Notes |
|---|---|---|
| **Go** | 1.22+ | [golang.org/dl](https://golang.org/dl/) |
| **Npcap** | Latest | [npcap.com](https://npcap.com/) — install in WinPcap API-compatible mode |
| **Git** | Any | For cloning |
| **Admin / root** | Required | Raw packet capture needs elevated privileges |
| **Windows** | 10/11 | Linux supported too (use `libpcap-dev`) |

> **Note:** On Windows, Npcap must be installed with _"Install Npcap in WinPcap API-compatible Mode"_ checked. The scanner **must be run as Administrator**.

---

## Quick Start

```powershell
# 1. Clone the repo
git clone https://github.com/yuvrajn05/QuantumSentry.git
cd QuantumSentry

# 2. Build the scanner (run as Administrator)
cd scanner
go build -o scanner.exe .

# 3. Build the backend
cd ../backend
go build -o server.exe .

# 4. Start the server (run as Administrator)
.\server.exe
```

Open **http://localhost:8080** in your browser.

Login with: `admin` / `QuantumSentry@Admin2026`

---

## Build Instructions

### Scanner

```powershell
cd scanner
go build -o scanner.exe .
```

The scanner binary must be placed at `scanner/scanner.exe` (relative to the backend). The backend invokes it as `../scanner/scanner.exe`.

**Run the scanner manually (for testing):**

```powershell
# Run as Administrator
.\scanner.exe google.com:443
```

This prints the full CBOM JSON to stdout.

### Backend

```powershell
cd backend
go build -o server.exe .
.\server.exe
```

On first startup, the server:
- Creates `quantumsentry.db` (SQLite database)
- Runs schema migrations (creates `scans`, `audit_log`, `users` tables)
- Seeds 3 default user accounts

The server listens on **port 8080**.

### Linux / macOS

```bash
cd scanner && go build -o scanner .
cd ../backend && go build -o server .
sudo ./server   # sudo required for raw packet capture
```

---

## Default Credentials

| Username | Password | Role | Permissions |
|---|---|---|---|
| `admin` | `QuantumSentry@Admin2026` | **Admin** | Full access: scan, bulk scan, history, audit |
| `auditor` | `QuantumSentry@Audit2026` | **Auditor** | Read-only: history, audit trail (no scanning) |
| `viewer` | `QuantumSentry@View2026` | **Viewer** | Scan only: run scans, see results |

> ⚠️ **Change these passwords before any public deployment.**

---

## API Reference

All endpoints except `/auth/login` require:
```
Authorization: Bearer <jwt_token>
```

### Authentication

| Method | Endpoint | Role | Description |
|---|---|---|---|
| `POST` | `/auth/login` | Public | Login, returns JWT token |
| `GET` | `/auth/me` | Any | Returns current user info from JWT |

**Login request:**
```json
POST /auth/login
{ "username": "admin", "password": "QuantumSentry@Admin2026" }
```

**Login response:**
```json
{ "token": "eyJ...", "username": "admin", "role": "admin" }
```

### Scanning

| Method | Endpoint | Role | Description |
|---|---|---|---|
| `GET` | `/scan?target=host:port` | admin, viewer | Single TLS scan, returns CBOM JSON |
| `POST` | `/scan/bulk` | admin, viewer | Bulk scan up to 20 targets |

**Bulk scan request:**
```json
POST /scan/bulk
{ "targets": ["google.com:443", "cloudflare.com:443", "github.com:443"] }
```

**Bulk scan response:**
```json
{
  "total": 3,
  "results": [
    { "target": "google.com:443", "status": "ok", "cbom": { ... } },
    { "target": "cloudflare.com:443", "status": "ok", "cbom": { ... } },
    { "target": "github.com:443", "status": "error", "error": "..." }
  ]
}
```

### History & Audit

| Method | Endpoint | Role | Description |
|---|---|---|---|
| `GET` | `/history` | admin, auditor | Last 50 scans (no CBOM blob) |
| `GET` | `/history/:id` | admin, auditor | Full CBOM for a single scan |
| `GET` | `/audit` | admin, auditor | Last 200 audit log entries |

---

## CBOM Schema

QuantumSentry generates a **Cryptographic Bill of Materials** fully compliant with the CERT-In SRS Annexure A schema.

```json
{
  "scan_id": "google.com:443-1711623001",
  "timestamp": "2026-03-28T17:38:00Z",
  "generator": "QuantumSentry v1.0",
  "assets": [{
    "asset_type": "network-endpoint",
    "host": "google.com",
    "port": 443,
    "source_ip": "192.168.1.5",
    "destination_ip": "142.250.192.46",
    "sni": "google.com",
    "alpn": ["h2", "http/1.1"],

    "algorithms": [{
      "asset_type": "algorithm",
      "name": "AES-128-GCM",
      "primitive": "symmetric",
      "mode": "GCM",
      "oid": "2.16.840.1.101.3.4.1.6"
    }],

    "protocols": [{
      "asset_type": "protocol",
      "name": "TLS",
      "version": "TLS 1.3",
      "oid": "1.3.18.0.2.32.104",
      "cipher_suite": "TLS_AES_128_GCM_SHA256",
      "selected_group": "X25519MLKEM768",
      "server_groups": ["X25519MLKEM768", "x25519"]
    }],

    "certificates": [{
      "asset_type": "certificate",
      "subject": "CN=*.google.com",
      "issuer": "CN=GTS CA 1C3",
      "serial_number": "...",
      "not_before": "2026-01-01T00:00:00Z",
      "not_after": "2026-03-31T00:00:00Z",
      "signature_algorithm": "ECDSA-SHA256",
      "signature_algorithm_ref": "1.2.840.10045.4.3.2",
      "public_key_algorithm": "EC P-256",
      "public_key_bits": 256,
      "certificate_format": "X.509",
      "certificate_extension": ".cer"
    }],

    "keys": [{
      "asset_type": "key",
      "name": "Server Public Key",
      "id": "sha256:ab12cd34ef56...",
      "algorithm": "EC P-256",
      "size": 256,
      "state": "active",
      "creation_date": "2026-01-01",
      "activation_date": "2026-01-01"
    }]
  }]
}
```

---

## Role-Based Access Control

```
Admin   ──► /scan  /scan/bulk  /history  /history/:id  /audit
Auditor ──►                    /history  /history/:id  /audit
Viewer  ──► /scan  /scan/bulk
```

**UI enforcement:**
- Auditors see the History and Audit Log buttons but **Scan buttons are disabled**
- Viewers can scan but will not see History/Audit buttons
- All tokens expire after 24 hours and the login modal reappears automatically

---

## Project Structure

```
QuantumSentry/
│
├── scanner/                    # Go — TLS scanner binary
│   ├── main.go                 # Entry point: TLS dial + pcap capture
│   ├── cbom/                   # CBOM generation package
│   │   ├── types.go            # Schema types (Annexure A compliant)
│   │   ├── algorithms.go       # OID registry, algorithm/protocol parsing
│   │   ├── builder.go          # Assembles CBOM from TLS session data
│   │   ├── input.go            # CLI argument parsing
│   │   └── utils.go            # Shared helpers (scan ID generation)
│   ├── utility/                # Network interface utilities
│   ├── go.mod
│   └── go.sum
│
├── backend/                    # Go — REST API server (Gin)
│   ├── main.go                 # Routes, auth middleware, scan invocation
│   ├── auth.go                 # JWT auth, bcrypt, RBAC middleware
│   ├── db.go                   # SQLite schema, scans/audit/users tables
│   ├── go.mod
│   └── go.sum
│
├── frontend/                   # Vanilla JS dashboard
│   ├── index.html              # SPA shell, login + audit modals
│   ├── script.js               # Dashboard logic, auth, render, bulk scan
│   └── style.css               # Dark-mode design system
│
├── iface_lister/               # Helper: list Npcap network interfaces
│
├── .gitignore
└── README.md
```

---

## Troubleshooting

### Scanner produces no output / `pcap` error
- **Cause:** Npcap not installed, or not running as Administrator
- **Fix:** Run PowerShell/terminal as Administrator, verify Npcap is installed in WinPcap-compatible mode

### `listen tcp :8080: bind: address already in use`
- **Cause:** Previous server instance still running
- **Fix:** `Stop-Job | Remove-Job` or kill the process on port 8080

### `401 Unauthorized` from API
- **Cause:** Missing or expired JWT token
- **Fix:** Sign out and sign back in; tokens expire after 24 hours

### Scan returns `error: exit status 1`
- **Cause:** Scanner binary not found at `../scanner/scanner.exe` relative to backend working directory
- **Fix:** Ensure you built the scanner (`go build -o scanner.exe .` in `scanner/`) and the backend is run from the `backend/` directory

### `Interface not found` on Windows
- **Cause:** Npcap interface GUID not auto-detected
- **Fix:** Run `iface_lister/iface_lister.exe` to list available interfaces and pass it via `--iface` flag

---

<div align="center">

**Built for PSB Cybersecurity Hackathon 2026**

_QuantumSentry — Securing India's banking infrastructure for the post-quantum era_

</div>
