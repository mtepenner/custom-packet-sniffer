package exporter

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestJSONExporter_WritesValidJSONLines(t *testing.T) {
	f, err := os.CreateTemp("", "capture-*.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	f.Close()
	defer os.Remove(path)

	exp, err := NewJSONExporter(path)
	if err != nil {
		t.Fatalf("NewJSONExporter: %v", err)
	}

	packets := []PacketInfo{
		{
			Timestamp: "2024-01-15T12:00:00Z",
			SrcMAC:    "00:11:22:33:44:55",
			DstMAC:    "66:77:88:99:aa:bb",
			SrcIP:     "192.168.1.1",
			DstIP:     "10.0.0.1",
			Protocol:  "TCP",
			SrcPort:   12345,
			DstPort:   80,
			Length:    60,
		},
		{
			Timestamp: "2024-01-15T12:00:01Z",
			SrcIP:     "172.16.0.1",
			DstIP:     "172.16.0.2",
			Protocol:  "UDP",
			SrcPort:   5353,
			DstPort:   53,
			Length:    42,
		},
	}

	for _, p := range packets {
		if err := exp.Export(p); err != nil {
			t.Fatalf("Export: %v", err)
		}
	}
	if err := exp.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Read back and verify each line is valid JSON
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	var decoded []PacketInfo
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var info PacketInfo
		if err := json.Unmarshal(scanner.Bytes(), &info); err != nil {
			t.Fatalf("invalid JSON line %q: %v", scanner.Text(), err)
		}
		decoded = append(decoded, info)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}

	if len(decoded) != len(packets) {
		t.Fatalf("expected %d lines, got %d", len(packets), len(decoded))
	}

	for i, p := range packets {
		if decoded[i].Timestamp != p.Timestamp {
			t.Errorf("line %d: Timestamp mismatch: %q vs %q", i, decoded[i].Timestamp, p.Timestamp)
		}
		if decoded[i].SrcIP != p.SrcIP {
			t.Errorf("line %d: SrcIP mismatch: %q vs %q", i, decoded[i].SrcIP, p.SrcIP)
		}
		if decoded[i].DstIP != p.DstIP {
			t.Errorf("line %d: DstIP mismatch: %q vs %q", i, decoded[i].DstIP, p.DstIP)
		}
		if decoded[i].Protocol != p.Protocol {
			t.Errorf("line %d: Protocol mismatch: %q vs %q", i, decoded[i].Protocol, p.Protocol)
		}
		if decoded[i].SrcPort != p.SrcPort {
			t.Errorf("line %d: SrcPort mismatch: %d vs %d", i, decoded[i].SrcPort, p.SrcPort)
		}
		if decoded[i].DstPort != p.DstPort {
			t.Errorf("line %d: DstPort mismatch: %d vs %d", i, decoded[i].DstPort, p.DstPort)
		}
		if decoded[i].Length != p.Length {
			t.Errorf("line %d: Length mismatch: %d vs %d", i, decoded[i].Length, p.Length)
		}
	}
}

func TestJSONExporter_AppendsToPreviousFile(t *testing.T) {
	f, err := os.CreateTemp("", "capture-*.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	f.Close()
	defer os.Remove(path)

	pkt := PacketInfo{Timestamp: "2024-01-15T12:00:00Z", Protocol: "TCP", Length: 60}

	// First write
	exp1, err := NewJSONExporter(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := exp1.Export(pkt); err != nil {
		t.Fatal(err)
	}
	if err := exp1.Close(); err != nil {
		t.Fatal(err)
	}

	// Second write (should append)
	exp2, err := NewJSONExporter(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := exp2.Export(pkt); err != nil {
		t.Fatal(err)
	}
	if err := exp2.Close(); err != nil {
		t.Fatal(err)
	}

	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	lineCount := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if scanner.Text() != "" {
			lineCount++
		}
	}
	if lineCount != 2 {
		t.Errorf("expected 2 lines after append, got %d", lineCount)
	}
}

func TestJSONExporter_OmitsEmptyOptionalFields(t *testing.T) {
	f, err := os.CreateTemp("", "capture-*.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	f.Close()
	defer os.Remove(path)

	exp, err := NewJSONExporter(path)
	if err != nil {
		t.Fatal(err)
	}
	// Only required fields populated
	pkt := PacketInfo{Timestamp: "2024-01-15T12:00:00Z", Protocol: "TCP", Length: 60}
	if err := exp.Export(pkt); err != nil {
		t.Fatal(err)
	}
	if err := exp.Close(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// Fields with omitempty should not appear when zero-valued
	line := string(data)
	for _, field := range []string{"src_mac", "dst_mac", "src_ip", "dst_ip", "app_payload"} {
		if strings.Contains(line, `"`+field+`"`) {
			t.Errorf("expected %q to be omitted when empty, but it was present in: %s", field, line)
		}
	}
	// src_port and dst_port with omitempty are int, 0 is omitted
	for _, field := range []string{"src_port", "dst_port"} {
		if strings.Contains(line, `"`+field+`"`) {
			t.Errorf("expected %q to be omitted when zero, but it was present in: %s", field, line)
		}
	}
}
