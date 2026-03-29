// Package main implements the QuantumSentry TLS/PQC scanner.
//
// QuantumSentry is a Post-Quantum Cryptography (PQC) readiness tool that
// connects to a target TLS endpoint and produces a structured
// Cryptographic Bill of Materials (CBOM) in JSON format.
//
// It operates in two parallel modes:
//
//  1. TLS dial (crypto/tls) — establishes an actual TLS connection to
//     extract negotiated protocol parameters: version, cipher suite,
//     selected KEM group, ALPN protocol, and the server certificate chain.
//
//  2. Raw packet capture (gopacket/pcap) — sniffs the outgoing ClientHello
//     on the wire to extract the full list of supported groups (key exchange
//     algorithms) advertised by the client, including any hybrid or pure
//     Post-Quantum groups (ML-KEM variants).
//
// Output is a CBOM JSON structure written to stdout, consumed by the backend.
//
// Usage:
//
//	./scanner [--iface <pcap-device>] <host:port>
//
// Examples:
//
//	./scanner google.com:443
//	./scanner --iface \Device\NPF_{...} example.com:443
package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"pqc-scanner/cbom"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// CertInfo holds a parsed summary of an X.509 server certificate,
// extracted from the TLS peer certificate chain.
type CertInfo struct {
	Subject            string
	Issuer             string
	NotBefore          time.Time
	NotAfter           time.Time
	SignatureAlgorithm string
	PublicKeyAlgorithm string
	PublicKeySize      int
	SerialNumber       string
	DNSNames           []string
	IsCA               bool
	KeyUsage           string
	ExtensionOIDs      []string
}

// ── TLS Version Helpers ──────────────────────────────────────────────────────

// decodeTLSVersion converts a TLS wire version uint16 into a human-readable string.
func decodeTLSVersion(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (%d)", version)
	}
}

// generatePublicKeyRef creates a short fingerprint (first 8 bytes of SHA-256)
// from the DER-encoded public key. Used as a stable reference ID in the CBOM.
func generatePublicKeyRef(cert *x509.Certificate) string {
	pubBytes, _ := x509.MarshalPKIXPublicKey(cert.PublicKey)
	hash := sha256.Sum256(pubBytes)
	return hex.EncodeToString(hash[:8])
}

// ── Key Exchange Group Helpers ───────────────────────────────────────────────

// getGroupName maps a uint16 TLS Supported Groups extension ID to a name.
// Covers classical ECDH groups as well as hybrid and pure ML-KEM (PQC) groups.
func getGroupName(id uint16) string {
	switch id {
	// Classical elliptic-curve Diffie-Hellman groups
	case 0x001d:
		return "X25519"
	case 0x0017:
		return "secp256r1"
	case 0x0018:
		return "secp384r1"
	case 0x0019:
		return "secp521r1"

	// Hybrid PQ + Classical (ML-KEM fused with classical ECDH)
	case 0x11eb:
		return "SecP256r1MLKEM768"
	case 0x11ec:
		return "X25519MLKEM768"
	case 0x11ed:
		return "SecP384r1MLKEM1024"

	// Pure Post-Quantum ML-KEM (NIST FIPS 203)
	case 0x0200:
		return "MLKEM512"
	case 0x0201:
		return "MLKEM768"
	case 0x0202:
		return "MLKEM1024"

	default:
		return fmt.Sprintf("Unknown(0x%04x)", id)
	}
}

// getCurveName maps a tls.CurveID (used in ConnectionState) to a group name.
// Mirrors getGroupName for the negotiated (selected) group after handshake.
func getCurveName(id tls.CurveID) string {
	switch id {
	case tls.X25519:
		return "X25519"
	case tls.CurveP256:
		return "secp256r1"
	case tls.CurveP384:
		return "secp384r1"
	case tls.CurveP521:
		return "secp521r1"
	case tls.CurveID(0x11eb):
		return "SecP256r1MLKEM768"
	case tls.CurveID(0x11ec):
		return "X25519MLKEM768"
	case tls.CurveID(0x11ed):
		return "SecP384r1MLKEM1024"
	case tls.CurveID(0x0200):
		return "MLKEM512"
	case tls.CurveID(0x0201):
		return "MLKEM768"
	case tls.CurveID(0x0202):
		return "MLKEM1024"
	default:
		return fmt.Sprintf("Unknown(0x%04x)", uint16(id))
	}
}

// firstOrEmpty returns the first string in a slice, or "" if the slice is empty.
func firstOrEmpty(arr []string) string {
	if len(arr) > 0 {
		return arr[0]
	}
	return ""
}

// ── Raw Packet Parsers ───────────────────────────────────────────────────────

// extractSupportedGroups parses the raw TLS ClientHello payload bytes and
// returns the list of key exchange groups the client advertised (extension 0x000a).
// This is used to detect PQC groups that would otherwise not be visible
// through the standard crypto/tls API.
func extractSupportedGroups(payload []byte) []string {
	var groups []string

	if len(payload) < 43 {
		return groups
	}

	handshake := payload[5:]
	if len(handshake) == 0 || handshake[0] != 0x01 { // 0x01 = ClientHello
		return groups
	}

	// Skip: handshake header (4) + legacy version (2) + random (32)
	idx := 4 + 2 + 32

	if len(handshake) < idx+1 {
		return groups
	}

	// Skip session ID
	sessionIDLen := int(handshake[idx])
	idx += 1 + sessionIDLen

	if len(handshake) < idx+2 {
		return groups
	}

	// Skip cipher suites
	csLen := int(handshake[idx])<<8 | int(handshake[idx+1])
	idx += 2 + csLen

	if len(handshake) < idx+1 {
		return groups
	}

	// Skip compression methods
	compLen := int(handshake[idx])
	idx += 1 + compLen

	if len(handshake) < idx+2 {
		return groups
	}

	// Walk TLS extensions
	extLen := int(handshake[idx])<<8 | int(handshake[idx+1])
	idx += 2

	end := idx + extLen
	if end > len(handshake) {
		end = len(handshake)
	}

	for idx+4 <= end {
		extType := int(handshake[idx])<<8 | int(handshake[idx+1])
		extSize := int(handshake[idx+2])<<8 | int(handshake[idx+3])
		idx += 4

		if idx+extSize > len(handshake) {
			return groups
		}

		// Extension type 0x000a = supported_groups
		if extType == 0x000a {
			if extSize < 2 {
				return groups
			}
			listLen := int(handshake[idx])<<8 | int(handshake[idx+1])
			pos := idx + 2

			for pos+1 < idx+2+listLen {
				groupID := uint16(handshake[pos])<<8 | uint16(handshake[pos+1])
				groups = append(groups, getGroupName(groupID))
				pos += 2
			}
		}

		idx += extSize
	}

	return groups
}

// extractSNI parses the SNI (Server Name Indication) from a raw TLS
// ClientHello payload (extension 0x0000). Returns "" if not found.
func extractSNI(payload []byte) string {
	if len(payload) < 43 {
		return ""
	}

	handshake := payload[5:]
	if len(handshake) == 0 || handshake[0] != 0x01 {
		return ""
	}

	idx := 4 + 2 + 32

	if len(handshake) < idx+1 {
		return ""
	}

	sessionIDLen := int(handshake[idx])
	idx += 1 + sessionIDLen

	if len(handshake) < idx+2 {
		return ""
	}

	csLen := int(handshake[idx])<<8 | int(handshake[idx+1])
	idx += 2 + csLen

	if len(handshake) < idx+1 {
		return ""
	}

	compLen := int(handshake[idx])
	idx += 1 + compLen

	if len(handshake) < idx+2 {
		return ""
	}

	extLen := int(handshake[idx])<<8 | int(handshake[idx+1])
	idx += 2

	end := idx + extLen
	if end > len(handshake) {
		end = len(handshake)
	}

	for idx+4 <= end {
		extType := int(handshake[idx])<<8 | int(handshake[idx+1])
		extSize := int(handshake[idx+2])<<8 | int(handshake[idx+3])
		idx += 4

		if idx+extSize > len(handshake) {
			return ""
		}

		// Extension type 0x0000 = server_name
		if extType == 0x0000 {
			if extSize < 5 {
				return ""
			}
			nameLen := int(handshake[idx+3])<<8 | int(handshake[idx+4])
			if idx+5+nameLen > len(handshake) {
				return ""
			}
			return string(handshake[idx+5 : idx+5+nameLen])
		}

		idx += extSize
	}

	return ""
}

// ── Certificate Helpers ──────────────────────────────────────────────────────

// getExtensionOIDs returns the OID string of every X.509 extension present
// in the certificate (e.g. "2.5.29.17" for Subject Alternative Name).
func getExtensionOIDs(cert *x509.Certificate) []string {
	var oids []string
	for _, ext := range cert.Extensions {
		oids = append(oids, ext.Id.String())
	}
	return oids
}

// certToInfo converts an x509.Certificate into the flat CertInfo struct
// used for CBOM construction.
func certToInfo(cert *x509.Certificate) CertInfo {
	return CertInfo{
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		PublicKeySize:      getPublicKeySize(cert),
		SerialNumber:       cert.SerialNumber.Text(16),
		DNSNames:           cert.DNSNames,
		IsCA:               cert.IsCA,
		KeyUsage:           parseKeyUsage(cert.KeyUsage),
		ExtensionOIDs:      getExtensionOIDs(cert),
	}
}

// parseKeyUsage converts an x509.KeyUsage bitmask into a human-readable string.
func parseKeyUsage(usage x509.KeyUsage) string {
	var usages []string

	if usage&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "DigitalSignature")
	}
	if usage&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "KeyEncipherment")
	}
	if usage&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "CertSign")
	}

	if len(usages) == 0 {
		return "Unknown"
	}

	return strings.Join(usages, ", ")
}

// getPublicKeySize returns the key size in bits for RSA, ECDSA, and Ed25519 keys.
func getPublicKeySize(cert *x509.Certificate) int {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return pub.Size() * 8
	case *ecdsa.PublicKey:
		return pub.Params().BitSize
	case ed25519.PublicKey:
		return 256
	default:
		return 0
	}
}

// ── Entry Point ──────────────────────────────────────────────────────────────

func main() {
	// Variables written by the TLS goroutine / pcap loop and read in the
	// certCh case handler. Channel synchronisation makes this safe.
	var (
		tlsVersion    string
		cipherSuite   string
		selectedGroup string
		alpn          string
		publicKeyRef  string
		srcIP         string
		dstIP         string
		sni           string
		groups        []string
	)

	// ── CLI flags ──────────────────────────────────────────────────────────
	deviceFlag := flag.String(
		"iface",
		`\Device\NPF_{4FE1FF45-8CDB-41C7-B42D-AC126CBD89BF}`,
		"Npcap/libpcap device name to capture on.\n"+
			"Run the iface_lister helper to enumerate available devices.",
	)
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		fmt.Println("Usage: ./scanner [--iface <device>] <host:port>")
		fmt.Println("Example: ./scanner google.com:443")
		return
	}

	target := args[0]
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		log.Fatal("Invalid target format — expected host:port (e.g. google.com:443)")
	}

	device := *deviceFlag

	// ── Packet capture setup ───────────────────────────────────────────────
	// Open a live capture handle on the specified interface.
	// snaplen=1600 bytes is sufficient to capture the full TLS ClientHello.
	handle, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// BPF filter: only capture TCP traffic to/from the target host on port 443.
	filter := fmt.Sprintf("tcp and host %s and port 443", host)
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	certCh := make(chan CertInfo, 1)
	errCh := make(chan error, 1)

	// ── TLS dial goroutine ─────────────────────────────────────────────────
	// We delay 200 ms before dialling so the for-select loop below has time
	// to start consuming packets. Without this delay the ClientHello would
	// have already been transmitted before the first read from packetSource.
	go func() {
		time.Sleep(200 * time.Millisecond)

		conn, err := tls.Dial("tcp", target, &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true, // We inspect; we do not verify
			// Advertise h2 and http/1.1 so the server negotiates ALPN.
			NextProtos: []string{"h2", "http/1.1"},
		})
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()

		state := conn.ConnectionState()

		// Extract TLS session parameters from the negotiated connection.
		tlsVersion    = decodeTLSVersion(state.Version)
		cipherSuite   = tls.CipherSuiteName(state.CipherSuite)
		selectedGroup = getCurveName(state.CurveID)
		alpn          = state.NegotiatedProtocol

		// Reliably populate network fields from the connection addresses.
		// pcap may have already captured these from the wire; we only fill
		// in blanks so pcap values take priority when available.
		localAddr  := conn.LocalAddr().String()
		remoteAddr := conn.RemoteAddr().String()

		if srcIP == "" {
			if h, _, e := net.SplitHostPort(localAddr); e == nil {
				srcIP = h
			} else {
				srcIP = localAddr
			}
		}
		if dstIP == "" {
			if h, _, e := net.SplitHostPort(remoteAddr); e == nil {
				dstIP = h
			} else {
				dstIP = remoteAddr
			}
		}
		if sni == "" {
			sni = host // SNI is always the hostname we dialled
		}

		if len(state.PeerCertificates) == 0 {
			errCh <- fmt.Errorf("no certificate found")
			return
		}

		publicKeyRef = generatePublicKeyRef(state.PeerCertificates[0])
		certCh <- certToInfo(state.PeerCertificates[0])
	}()

	timeout := time.After(8 * time.Second)

	// ── Event loop ─────────────────────────────────────────────────────────
	for {
		select {

		// Inspect every captured packet for TLS handshake content.
		case packet := <-packetSource.Packets():
			ipLayer  := packet.Layer(layers.LayerTypeIPv4)
			tcpLayer := packet.Layer(layers.LayerTypeTCP)

			if ipLayer == nil || tcpLayer == nil {
				continue
			}

			ip  := ipLayer.(*layers.IPv4)
			tcp := tcpLayer.(*layers.TCP)

			if len(tcp.Payload) == 0 {
				continue
			}

			payload := tcp.Payload

			// TLS record header byte 0x16 = Handshake.
			// Parse the ClientHello to get supported groups and SNI.
			if payload[0] == 0x16 {
				srcIP  = ip.SrcIP.String()
				dstIP  = ip.DstIP.String()
				sni    = extractSNI(payload)
				groups = extractSupportedGroups(payload)
			}

		// TLS dial completed — assemble and emit the CBOM.
		case cert := <-certCh:
			input := cbom.ScanInput{
				Host: target,

				// Network layer (from pcap or connection fallback)
				SourceIP:      srcIP,
				DestinationIP: dstIP,
				SNI:           sni,

				// TLS session parameters
				TLSVersion:      tlsVersion,
				CipherSuite:     cipherSuite,
				SelectedGroup:   selectedGroup,
				SupportedGroups: groups,
				ALPN:            alpn,

				// Certificate fields
				Subject: cert.Subject,
				Issuer:  cert.Issuer,

				ValidFrom: cert.NotBefore.Format(time.RFC3339),
				ValidTo:   cert.NotAfter.Format(time.RFC3339),

				SerialNumber: cert.SerialNumber,

				SignatureAlgorithm: cert.SignatureAlgorithm,

				PublicKeyAlgorithm: cert.PublicKeyAlgorithm,
				PublicKeySize:      cert.PublicKeySize,

				IsCA: cert.IsCA,

				DNSNames:   cert.DNSNames,
				DNSCount:   len(cert.DNSNames),
				PrimaryDNS: firstOrEmpty(cert.DNSNames),

				KeyUsage:    []string{cert.KeyUsage},
				ExtKeyUsage: []string{},

				OIDs: cert.ExtensionOIDs,

				PublicKeyRef: publicKeyRef,
			}

			// Build the CBOM and emit it as indented JSON to stdout.
			cbomObj := cbom.BuildFromScan(input)
			jsonBytes, _ := json.MarshalIndent(cbomObj, "", "  ")
			fmt.Println(string(jsonBytes))
			return

		// TLS dial failed (e.g. connection refused, certificate error).
		case err := <-errCh:
			log.Println("TLS error:", err)
			return

		// Hard timeout — prevent hanging indefinitely on filtered ports.
		case <-timeout:
			fmt.Println(`{"error":"Timeout: scan did not complete within 8s"}`)
			return
		}
	}
}