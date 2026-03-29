// Package cbom defines the Cryptographic Bill of Materials (CBOM) data model.
//
// The schema follows the CERT-In minimum elements specification (Annexure A of
// the PSB Cybersecurity Hackathon 2026 SRS) and maps to the CycloneDX CBOM
// standard. Every object includes an "asset_type" field to identify its role
// within the inventory.
package cbom

// ScanRun is the top-level CBOM output for a single scan job.
type ScanRun struct {
	ScanID    string  `json:"scan_id"`
	Timestamp string  `json:"timestamp"`
	Target    string  `json:"target"`
	Assets    []Asset `json:"assets"`
}

// Asset represents a single public-facing cryptographic asset (e.g. a web
// server endpoint) and groups all its crypto inventory together.
type Asset struct {
	Host string `json:"host"`

	Network NetworkInfo `json:"network"`

	Protocols    []Protocol    `json:"protocols"`
	Certificates []Certificate `json:"certificates"`

	// Keys holds the cryptographic keys discovered on this asset.
	// Populated from the server certificate's public key.
	Keys []CryptoKey `json:"keys,omitempty"`
}

// NetworkInfo captures layer-3/4 context from the packet capture.
type NetworkInfo struct {
	SourceIP      string `json:"source_ip,omitempty"`
	DestinationIP string `json:"destination_ip,omitempty"`
	SNI           string `json:"sni,omitempty"`
}

// Protocol captures the TLS session parameters negotiated during the handshake.
// asset_type is always "protocol".
type Protocol struct {
	AssetType string `json:"asset_type"` // always "protocol"
	Name      string `json:"name"`

	Version     string `json:"version"`
	CipherSuite string `json:"cipher_suite"`

	// OID for TLS 1.3 protocol: 1.3.18.0.2.32.104
	OID string `json:"oid,omitempty"`

	SelectedGroup   string   `json:"selected_group,omitempty"`
	SupportedGroups []string `json:"supported_groups,omitempty"`

	ALPN string `json:"alpn,omitempty"`

	Algorithms []Algorithm `json:"algorithms"`
}

// Certificate holds the X.509 certificate metadata for a server certificate.
// asset_type is always "certificate".
type Certificate struct {
	AssetType string `json:"asset_type"` // always "certificate"

	Subject string `json:"subject"`
	Issuer  string `json:"issuer"`

	ValidFrom string `json:"valid_from"`
	ValidTo   string `json:"valid_to"` // "Not Valid After" per SRS

	SerialNumber string `json:"serial_number"`

	// SignatureAlgorithm is the human-readable name (e.g. "SHA256-RSA").
	SignatureAlgorithm string `json:"signature_algorithm"`
	// SignatureAlgorithmRef is the OID of the signature algorithm.
	SignatureAlgorithmRef string `json:"signature_algorithm_ref,omitempty"`

	PublicKeyAlgorithm string `json:"public_key_algorithm"`
	PublicKeySize      int    `json:"public_key_size"`
	// PublicKeyRef links to the CryptoKey ID in the Keys[] array.
	PublicKeyRef string `json:"public_key_ref,omitempty"`

	IsCA bool `json:"is_ca"`

	DNSNames   []string `json:"dns_names,omitempty"`
	DNSCount   int      `json:"dns_count,omitempty"`
	PrimaryDNS string   `json:"primary_dns,omitempty"`

	KeyUsage    []string `json:"key_usage,omitempty"`
	ExtKeyUsage []string `json:"ext_key_usage,omitempty"`

	OIDs []string `json:"oids,omitempty"`

	// CertificateFormat is always "X.509" for TLS server certificates.
	CertificateFormat string `json:"certificate_format"`
	// CertificateExtension is the common file extension for this cert type.
	CertificateExtension string `json:"certificate_extension"`
}

// CryptoKey represents a cryptographic key discovered on an asset.
// Corresponds to the "Keys" section of the CERT-In CBOM Annexure A.
// asset_type is always "key".
type CryptoKey struct {
	AssetType string `json:"asset_type"` // always "key"

	// Name is derived from the certificate subject CN.
	Name string `json:"name"`

	// ID is a fingerprint (first 8 bytes of SHA-256 of the public key DER).
	ID string `json:"id"`

	// Value is intentionally omitted for security — private keys are never stored.
	Value string `json:"value"` // always ""

	// Size is the key length in bits (e.g. 256 for EC P-256, 2048 for RSA-2048).
	Size int `json:"size"`

	// Algorithm is the key algorithm (e.g. "RSA", "ECDSA", "Ed25519").
	Algorithm string `json:"algorithm"`

	// State reflects the key's lifecycle status derived from the cert validity.
	// Values: "active", "expired", "revoked"
	State string `json:"state"`

	// CreationDate is the certificate NotBefore date (proxy for key creation).
	CreationDate string `json:"creation_date"`
	// ActivationDate mirrors CreationDate — when the key became operational.
	ActivationDate string `json:"activation_date"`
}

// Algorithm describes a cryptographic algorithm used within a protocol or cipher suite.
// Corresponds to the "Algorithms" section of the CERT-In CBOM Annexure A.
// asset_type is always "algorithm".
type Algorithm struct {
	AssetType string `json:"asset_type"` // always "algorithm"

	// Name is the full descriptive name, e.g. "AES-128-GCM" not just "AES".
	Name string `json:"name"`

	// Primitive uses NIST/IETF vocabulary: "symmetric", "hash", "signature",
	// "key-encapsulation", "key-agreement", "mac".
	Primitive string `json:"primitive"`

	// Mode is the operational mode, e.g. "GCM" for AES-GCM.
	Mode string `json:"mode,omitempty"`

	// CryptoFunctions lists supported operations, e.g. ["encrypt","decrypt","auth"].
	CryptoFunctions []string `json:"crypto_functions,omitempty"`

	// ClassicalSecBits is the classical security level in bits.
	ClassicalSecBits int `json:"security_bits,omitempty"`

	// OID is the globally unique Object Identifier for this algorithm.
	OID string `json:"oid,omitempty"`
}