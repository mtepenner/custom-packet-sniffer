# Custom Packet Sniffer

A lightweight, custom network packet sniffer written in Go. This tool leverages the Google `gopacket` library and `libpcap` to capture live network traffic, decode various networking layers, extract application-layer payloads, and export the structured packet data into JSON lines (JSONL) or SQLite databases.

## 📑 Table of Contents
- [Features](#-features)
- [Technologies Used](#-technologies-used)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Usage](#-usage)
- [Project Structure](#-project-structure)
- [Contributing](#-contributing)
- [License](#-license)

## 🚀 Features
* **Live Packet Capture**: Intercept network traffic on specified interfaces (e.g., `eth0`, `lo`, `wlan0`) using `libpcap`.
* **BPF Filtering**: Apply Berkeley Packet Filters (BPF) to narrow down captures (e.g., `"tcp port 80 or tcp port 443"`).
* **Multi-Layer Decoding**: Automatically parses Ethernet (MAC addresses), IP (IPv4/IPv6), and Transport (TCP/UDP ports) layers.
* **Payload Extraction**: Applies simple heuristics to extract readable text or HTTP headers from the application layer payload.
* **Flexible Exporters**: Saves captured packet information locally via a `JSONExporter` (JSONL format) or an `SQLiteExporter` (local SQLite database).
* **Graceful Shutdown**: Safely catches `Ctrl+C` (SIGTERM/Interrupt) to cleanly halt the capture loop and close file streams.

## 💻 Technologies Used
* **[Go 1.21](https://go.dev/)**: Core programming language.
* **[google/gopacket](https://github.com/google/gopacket)**: Packet decoding and `pcap` bindings.
* **[mattn/go-sqlite3](https://github.com/mattn/go-sqlite3)**: Database driver for SQLite exports.

## ⚙️ Prerequisites
Because this project utilizes `gopacket` and `pcap`, you must have the `libpcap` headers installed on your system.

* **Ubuntu/Debian**: `sudo apt-get install libpcap-dev`
* **macOS**: `brew install libpcap`
* **Go**: Version 1.21 or higher.

## 🛠️ Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/mtepenner/custom-packet-sniffer.git
   cd custom-packet-sniffer
   ```

2. **Download dependencies:**
   ```bash
   make deps
   ```
   *(Alternatively: `go mod tidy`)*

3. **Build the binary:**
   ```bash
   make build
   ```
   This will compile the application and output the executable to `bin/sniffer`.

## 💡 Usage

Running a packet sniffer generally requires root/administrator privileges. 

**Basic Run Command:**
```bash
sudo ./bin/sniffer -i eth0 -f "tcp port 80" -o my_capture.jsonl
```

**CLI Flags:**
* `-i`: Network interface to sniff (default: `eth0`)
* `-f`: BPF filter string (default: none)
* `-o`: Output JSON lines file (default: `capture.jsonl`)

**Using the Makefile:**
You can use the built-in `Makefile` to quickly build and run a test capture on the loopback interface (`lo`) filtering for HTTP/HTTPS traffic:
```bash
make run
```

## 🏗️ Project Structure
* `cmd/sniffer/`: Application entry point and CLI initialization.
* `internal/capture/`: Pcap engine handling the live packet stream loop.
* `internal/exporter/`: Output handlers containing interfaces for JSON and SQLite formatting.
* `internal/parser/`: Decodes raw packets into structured layer data and extracts readable payloads.

## 🤝 Contributing
Contributions are welcome! Please feel free to submit a Pull Request or open an Issue for any bugs or feature requests (like new protocol decoders).

## 📄 License
This project is licensed under the MIT License. See the `LICENSE` file for details.
