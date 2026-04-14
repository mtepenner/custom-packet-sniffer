package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/yourusername/packet-sniffer/internal/capture"
	"github.com/yourusername/packet-sniffer/internal/exporter"
)

func main() {
	// CLI Flags
	iface := flag.String("i", "eth0", "Network interface to sniff (e.g., eth0, wlan0, lo)")
	bpf := flag.String("f", "", "BPF filter (e.g., 'tcp port 80')")
	outFile := flag.String("o", "capture.jsonl", "Output JSON lines file")
	flag.Parse()

	// 1. Initialize Exporter
	exp, err := exporter.NewJSONExporter(*outFile)
	if err != nil {
		log.Fatalf("Failed to initialize JSON exporter: %v", err)
	}
	defer exp.Close()

	// 2. Setup graceful shutdown channel (Catches Ctrl+C)
	stopChan := make(chan struct{})
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		close(stopChan) // Signal the capture loop to stop
	}()

	// 3. Start Capturing (This blocks until stopChan is closed)
	err = capture.StartLiveCapture(*iface, *bpf, exp, stopChan)
	if err != nil {
		log.Fatalf("Capture error: %v", err)
	}

	fmt.Printf("Capture saved to %s\n", *outFile)
}
