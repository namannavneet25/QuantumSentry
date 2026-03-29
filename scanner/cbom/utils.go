package cbom

import (
	"fmt"
	"time"
)

// GenerateScanID creates a unique scan identifier from the host and current
// Unix timestamp, e.g. "google.com:443-1711623001".
func GenerateScanID(host string) string {
	return fmt.Sprintf("%s-%d", host, time.Now().Unix())
}