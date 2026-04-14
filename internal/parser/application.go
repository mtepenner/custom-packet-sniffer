package parser

import (
	"strings"
	"unicode"
)

// ExtractApplicationData attempts to grab readable text from the payload.
// For a production tool, you would implement proper protocol decoders (HTTP, DNS) here.
func ExtractApplicationData(payload []byte) string {
	if len(payload) == 0 {
		return ""
	}

	// Simple heuristic: If it starts with an HTTP method, extract the first line.
	payloadStr := string(payload)
	if strings.HasPrefix(payloadStr, "GET ") || strings.HasPrefix(payloadStr, "POST ") || strings.HasPrefix(payloadStr, "HTTP/") {
		lines := strings.SplitN(payloadStr, "\r\n", 2)
		return lines[0]
	}

	// Otherwise, return a snippet of printable characters (useful for spotting cleartext credentials)
	var readable strings.Builder
	for i, b := range payload {
		if i > 64 { // Limit payload snippet size
			readable.WriteString("...")
			break
		}
		if unicode.IsPrint(rune(b)) {
			readable.WriteByte(b)
		} else {
			readable.WriteByte('.')
		}
	}
	
	return readable.String()
}
