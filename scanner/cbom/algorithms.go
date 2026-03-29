// Package cbom — algorithms.go
//
// ExtractAlgorithms parses a TLS cipher suite string and returns a list of
// Algorithm objects with full CERT-In CBOM Annexure A compliant fields:
// full name, asset_type, primitive, mode, crypto functions, security bits, and OID.
//
// Algorithm OID reference:
//   AES-128-GCM  : 2.16.840.1.101.3.4.1.6
//   AES-256-GCM  : 2.16.840.1.101.3.4.1.46
//   AES-128-CCM  : 2.16.840.1.101.3.4.1.7
//   AES-256-CCM  : 2.16.840.1.101.3.4.1.47
//   ChaCha20-Poly1305 : 1.2.840.113549.1.9.16.3.18
//   RSA          : 1.2.840.113549.1.1.1
//   ECDHE        : 1.2.840.10045.2.1
//   SHA-256      : 2.16.840.1.101.3.4.2.1
//   SHA-384      : 2.16.840.1.101.3.4.2.2
//   HMAC-SHA256  : 1.2.840.113549.2.9
package cbom

import "strings"

// ExtractAlgorithms parses a TLS cipher suite string (e.g. "TLS_AES_128_GCM_SHA256")
// and returns a slice of fully-populated Algorithm objects.
func ExtractAlgorithms(cipher string) []Algorithm {
	var algos []Algorithm
	c := strings.ToUpper(cipher)

	// ── Symmetric Encryption Algorithms ─────────────────────────────────────

	if strings.Contains(c, "AES_128_GCM") || strings.Contains(c, "AES-128-GCM") {
		algos = append(algos, Algorithm{
			AssetType:        "algorithm",
			Name:             "AES-128-GCM",
			Primitive:        "symmetric",
			Mode:             "GCM",
			CryptoFunctions:  []string{"encrypt", "decrypt", "authenticate"},
			ClassicalSecBits: 128,
			OID:              "2.16.840.1.101.3.4.1.6",
		})
	} else if strings.Contains(c, "AES_256_GCM") || strings.Contains(c, "AES-256-GCM") {
		algos = append(algos, Algorithm{
			AssetType:        "algorithm",
			Name:             "AES-256-GCM",
			Primitive:        "symmetric",
			Mode:             "GCM",
			CryptoFunctions:  []string{"encrypt", "decrypt", "authenticate"},
			ClassicalSecBits: 256,
			OID:              "2.16.840.1.101.3.4.1.46",
		})
	} else if strings.Contains(c, "AES_128_CCM") || strings.Contains(c, "AES-128-CCM") {
		algos = append(algos, Algorithm{
			AssetType:        "algorithm",
			Name:             "AES-128-CCM",
			Primitive:        "symmetric",
			Mode:             "CCM",
			CryptoFunctions:  []string{"encrypt", "decrypt", "authenticate"},
			ClassicalSecBits: 128,
			OID:              "2.16.840.1.101.3.4.1.7",
		})
	} else if strings.Contains(c, "AES_256_CCM") || strings.Contains(c, "AES-256-CCM") {
		algos = append(algos, Algorithm{
			AssetType:        "algorithm",
			Name:             "AES-256-CCM",
			Primitive:        "symmetric",
			Mode:             "CCM",
			CryptoFunctions:  []string{"encrypt", "decrypt", "authenticate"},
			ClassicalSecBits: 256,
			OID:              "2.16.840.1.101.3.4.1.47",
		})
	} else if strings.Contains(c, "AES") {
		// Fallback for any other AES variant
		mode := ""
		if strings.Contains(c, "GCM") {
			mode = "GCM"
		} else if strings.Contains(c, "CBC") {
			mode = "CBC"
		} else if strings.Contains(c, "CCM") {
			mode = "CCM"
		}
		algos = append(algos, Algorithm{
			AssetType:        "algorithm",
			Name:             "AES-" + mode,
			Primitive:        "symmetric",
			Mode:             mode,
			CryptoFunctions:  []string{"encrypt", "decrypt"},
			ClassicalSecBits: 128,
			OID:              "2.16.840.1.101.3.4.1.6",
		})
	}

	if strings.Contains(c, "CHACHA20") {
		algos = append(algos, Algorithm{
			AssetType:        "algorithm",
			Name:             "ChaCha20-Poly1305",
			Primitive:        "symmetric",
			Mode:             "stream",
			CryptoFunctions:  []string{"encrypt", "decrypt", "authenticate"},
			ClassicalSecBits: 256,
			OID:              "1.2.840.113549.1.9.16.3.18",
		})
	}

	// ── Key Exchange / Key Agreement ─────────────────────────────────────────

	if strings.Contains(c, "ECDHE") || strings.Contains(c, "ECDH") {
		algos = append(algos, Algorithm{
			AssetType:        "algorithm",
			Name:             "ECDHE",
			Primitive:        "key-agreement",
			CryptoFunctions:  []string{"key_agreement"},
			ClassicalSecBits: 128,
			OID:              "1.2.840.10045.2.1",
		})
	}

	if strings.Contains(c, "DHE") && !strings.Contains(c, "ECDHE") {
		algos = append(algos, Algorithm{
			AssetType:        "algorithm",
			Name:             "DHE",
			Primitive:        "key-agreement",
			CryptoFunctions:  []string{"key_agreement"},
			ClassicalSecBits: 112,
			OID:              "1.2.840.10046.2.1",
		})
	}

	// ── Asymmetric / Authentication ───────────────────────────────────────────

	if strings.Contains(c, "RSA") {
		algos = append(algos, Algorithm{
			AssetType:        "algorithm",
			Name:             "RSA",
			Primitive:        "signature",
			CryptoFunctions:  []string{"encrypt", "decrypt", "sign", "verify"},
			ClassicalSecBits: 112,
			OID:              "1.2.840.113549.1.1.1",
		})
	}

	if strings.Contains(c, "ECDSA") {
		algos = append(algos, Algorithm{
			AssetType:        "algorithm",
			Name:             "ECDSA",
			Primitive:        "signature",
			CryptoFunctions:  []string{"sign", "verify"},
			ClassicalSecBits: 128,
			OID:              "1.2.840.10045.4.3.2",
		})
	}

	// ── Hash / MAC ────────────────────────────────────────────────────────────

	if strings.Contains(c, "SHA256") || strings.Contains(c, "SHA384") || strings.Contains(c, "SHA") {
		name := "SHA-256"
		oid := "2.16.840.1.101.3.4.2.1"
		bits := 128
		if strings.Contains(c, "SHA384") {
			name = "SHA-384"
			oid = "2.16.840.1.101.3.4.2.2"
			bits = 192
		} else if strings.Contains(c, "SHA512") {
			name = "SHA-512"
			oid = "2.16.840.1.101.3.4.2.3"
			bits = 256
		}
		algos = append(algos, Algorithm{
			AssetType:        "algorithm",
			Name:             name,
			Primitive:        "hash",
			CryptoFunctions:  []string{"digest"},
			ClassicalSecBits: bits,
			OID:              oid,
		})
	}

	return algos
}

// AlgorithmOIDForSigAlgo returns the OID for a certificate signature algorithm
// string as returned by x509.Certificate.SignatureAlgorithm.String().
func AlgorithmOIDForSigAlgo(sigAlgo string) string {
	switch sigAlgo {
	case "SHA256-RSA", "SHA256WithRSA":
		return "1.2.840.113549.1.1.11"
	case "SHA384-RSA", "SHA384WithRSA":
		return "1.2.840.113549.1.1.12"
	case "SHA512-RSA", "SHA512WithRSA":
		return "1.2.840.113549.1.1.13"
	case "ECDSA-SHA256", "ECDSAWithSHA256":
		return "1.2.840.10045.4.3.2"
	case "ECDSA-SHA384", "ECDSAWithSHA384":
		return "1.2.840.10045.4.3.3"
	case "Ed25519":
		return "1.3.101.112"
	case "Ed448":
		return "1.3.101.113"
	default:
		return ""
	}
}

// TLSProtocolOID returns the OID for a TLS protocol version string.
func TLSProtocolOID(version string) string {
	switch version {
	case "TLS 1.3":
		return "1.3.18.0.2.32.104"
	case "TLS 1.2":
		return "1.3.18.0.2.32.103"
	case "TLS 1.1":
		return "1.3.18.0.2.32.102"
	case "TLS 1.0":
		return "1.3.18.0.2.32.101"
	default:
		return ""
	}
}