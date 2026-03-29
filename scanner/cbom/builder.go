// Package cbom — builder.go
//
// BuildFromScan assembles a fully-compliant CBOM ScanRun from a flat ScanInput.
// All asset_type fields, OIDs, Keys[], and certificate metadata are populated
// to satisfy the CERT-In CBOM Annexure A requirements.
package cbom

import (
	"strings"
	"time"
)

// BuildFromScan assembles a CBOM ScanRun from a flat ScanInput produced by the scanner.
func BuildFromScan(input ScanInput) ScanRun {

	// ── Protocol ──────────────────────────────────────────────────────────────
	protocol := Protocol{
		AssetType:       "protocol",
		Name:            "TLS",
		Version:         input.TLSVersion,
		CipherSuite:     input.CipherSuite,
		OID:             TLSProtocolOID(input.TLSVersion),
		SelectedGroup:   input.SelectedGroup,
		SupportedGroups: input.SupportedGroups,
		ALPN:            input.ALPN,
		Algorithms:      ExtractAlgorithms(input.CipherSuite),
	}

	// ── Certificate ───────────────────────────────────────────────────────────
	cert := Certificate{
		AssetType: "certificate",

		Subject:      input.Subject,
		Issuer:       input.Issuer,
		ValidFrom:    input.ValidFrom,
		ValidTo:      input.ValidTo,
		SerialNumber: input.SerialNumber,

		SignatureAlgorithm:    input.SignatureAlgorithm,
		SignatureAlgorithmRef: AlgorithmOIDForSigAlgo(input.SignatureAlgorithm),

		PublicKeyAlgorithm: input.PublicKeyAlgorithm,
		PublicKeySize:      input.PublicKeySize,
		PublicKeyRef:       input.PublicKeyRef, // fingerprint set by scanner

		IsCA: input.IsCA,

		DNSNames:   input.DNSNames,
		DNSCount:   input.DNSCount,
		PrimaryDNS: input.PrimaryDNS,

		KeyUsage:    input.KeyUsage,
		ExtKeyUsage: input.ExtKeyUsage,

		OIDs: input.OIDs,

		// CERT-In Annexure A mandatory fields
		CertificateFormat:    "X.509",
		CertificateExtension: ".cer",
	}

	// ── Keys — derive from certificate public key ─────────────────────────────
	// The key state is calculated from the certificate validity window.
	keyState := deriveKeyState(input.ValidFrom, input.ValidTo)

	// Extract the common name (CN) from the subject string for the key name.
	keyName := extractCN(input.Subject)
	if keyName == "" {
		keyName = input.Host
	}

	cryptoKey := CryptoKey{
		AssetType:      "key",
		Name:           keyName,
		ID:             input.PublicKeyRef, // same SHA-256 fingerprint
		Value:          "",                // never stored — security best practice
		Size:           input.PublicKeySize,
		Algorithm:      input.PublicKeyAlgorithm,
		State:          keyState,
		CreationDate:   input.ValidFrom, // cert NotBefore ≈ key creation date
		ActivationDate: input.ValidFrom,
	}

	// ── Asset ─────────────────────────────────────────────────────────────────
	asset := Asset{
		Host: input.Host,

		Network: NetworkInfo{
			SourceIP:      input.SourceIP,
			DestinationIP: input.DestinationIP,
			SNI:           input.SNI,
		},

		Protocols:    []Protocol{protocol},
		Certificates: []Certificate{cert},
		Keys:         []CryptoKey{cryptoKey},
	}

	// ── ScanRun ───────────────────────────────────────────────────────────────
	return ScanRun{
		ScanID:    GenerateScanID(input.Host),
		Timestamp: time.Now().Format(time.RFC3339),
		Target:    input.Host,
		Assets:    []Asset{asset},
	}
}

// deriveKeyState calculates key lifecycle state from validity dates.
// Returns "active", "expired", or "unknown".
func deriveKeyState(validFrom, validTo string) string {
	now := time.Now()

	to, err := time.Parse(time.RFC3339, validTo)
	if err != nil {
		return "unknown"
	}
	if now.After(to) {
		return "expired"
	}

	from, err := time.Parse(time.RFC3339, validFrom)
	if err != nil {
		return "unknown"
	}
	if now.Before(from) {
		return "pending"
	}

	return "active"
}

// extractCN pulls the CN= value from an X.509 Distinguished Name string.
// e.g. "CN=*.google.com,O=Google LLC,C=US" → "*.google.com"
func extractCN(dn string) string {
	for _, part := range strings.Split(dn, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToUpper(part), "CN=") {
			return strings.TrimPrefix(strings.TrimPrefix(part, "CN="), "cn=")
		}
	}
	return ""
}