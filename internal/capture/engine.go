package capture

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/yourusername/packet-sniffer/internal/exporter"
	"github.com/yourusername/packet-sniffer/internal/parser"
)

// StartLiveCapture opens a network interface and begins reading packets.
func StartLiveCapture(device string, bpfFilter string, exp exporter.Exporter, stopChan chan struct{}) error {
	// Open the device. Parameters: device name, snapshot length (max bytes per packet), promiscuous mode, timeout
	handle, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open device %s: %v", device, err)
	}
	defer handle.Close()

	// Apply BPF (Berkeley Packet Filter) if provided (e.g., "tcp and port 80")
	if bpfFilter != "" {
		if err := handle.SetBPFFilter(bpfFilter); err != nil {
			return fmt.Errorf("failed to set BPF filter: %v", err)
		}
	}

	fmt.Printf("Started capturing on %s (Filter: '%s')...\n", device, bpfFilter)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	for {
		select {
		case <-stopChan:
			fmt.Println("\nStopping capture engine...")
			return nil
		case packet := <-packets:
			if packet == nil {
				continue
			}
			
			// Decode the packet
			info := parser.DecodePacket(packet)
			
			// Export the result
			if err := exp.Export(info); err != nil {
				fmt.Printf("Failed to export packet: %v\n", err)
			}
		}
	}
}
