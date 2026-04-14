.PHONY: build run clean deps

BINARY_NAME=sniffer

build:
	@echo "Building Sniffer (Requires libpcap)..."
	go build -o bin/$(BINARY_NAME) cmd/sniffer/main.go

# Example run command testing loopback with a BPF filter for port 80 or 443
run: build
	sudo ./bin/$(BINARY_NAME) -i lo -f "tcp port 80 or tcp port 443"

deps:
	go mod tidy

clean:
	go clean
	rm -rf bin/
	rm -f capture.jsonl
