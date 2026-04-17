package parser

import (
	"strings"
	"testing"
)

func TestExtractApplicationData_Empty(t *testing.T) {
	result := ExtractApplicationData([]byte{})
	if result != "" {
		t.Errorf("expected empty string for empty payload, got %q", result)
	}
}

func TestExtractApplicationData_HTTPGet(t *testing.T) {
	payload := []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
	result := ExtractApplicationData(payload)
	if result != "GET /index.html HTTP/1.1" {
		t.Errorf("expected first HTTP request line, got %q", result)
	}
}

func TestExtractApplicationData_HTTPPost(t *testing.T) {
	payload := []byte("POST /login HTTP/1.1\r\nHost: example.com\r\n\r\n")
	result := ExtractApplicationData(payload)
	if result != "POST /login HTTP/1.1" {
		t.Errorf("expected first HTTP request line, got %q", result)
	}
}

func TestExtractApplicationData_HTTPResponse(t *testing.T) {
	payload := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n")
	result := ExtractApplicationData(payload)
	if result != "HTTP/1.1 200 OK" {
		t.Errorf("expected HTTP response status line, got %q", result)
	}
}

func TestExtractApplicationData_Printable(t *testing.T) {
	payload := []byte("hello world")
	result := ExtractApplicationData(payload)
	if result != "hello world" {
		t.Errorf("expected printable payload unchanged, got %q", result)
	}
}

func TestExtractApplicationData_NonPrintable(t *testing.T) {
	// Binary payload should replace non-printable bytes with '.'
	payload := []byte{0x01, 0x02, 0x41, 0x03} // only 'A' (0x41) is printable
	result := ExtractApplicationData(payload)
	if result != "..A." {
		t.Errorf("expected non-printable bytes replaced with '.', got %q", result)
	}
}

func TestExtractApplicationData_LongPayloadTruncated(t *testing.T) {
	// Payload longer than 65 bytes should be truncated with "..."
	// The loop writes bytes at indices 0-64 (65 bytes), then appends "..." on index 65.
	payload := []byte(strings.Repeat("A", 100))
	result := ExtractApplicationData(payload)
	if !strings.HasSuffix(result, "...") {
		t.Errorf("expected long payload to be truncated with '...', got %q", result)
	}
	// Should have 65 'A' chars + "..."
	expected := strings.Repeat("A", 65) + "..."
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestExtractApplicationData_ExactlyAtLimit(t *testing.T) {
	// Payload of exactly 65 bytes should NOT be truncated
	payload := []byte(strings.Repeat("B", 65))
	result := ExtractApplicationData(payload)
	if strings.HasSuffix(result, "...") {
		t.Errorf("payload of exactly 65 bytes should not be truncated, got %q", result)
	}
	if len(result) != 65 {
		t.Errorf("expected length 65, got %d", len(result))
	}
}
