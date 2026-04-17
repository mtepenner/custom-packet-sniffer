package parser

import (
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/mtepenner/custom-packet-sniffer/internal/exporter"
)

// DecodePacket takes a raw gopacket and extracts the relevant layers into our PacketInfo struct.
func DecodePacket(packet gopacket.Packet) exporter.PacketInfo {
	// Use nanosecond precision to accurately represent the packet capture time.
	ts := packet.Metadata().Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	info := exporter.PacketInfo{
		Timestamp: ts.UTC().Format(time.RFC3339Nano),
		Length:    packet.Metadata().Length,
	}

	// 1. Parse Ethernet Layer (MAC Addresses)
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth, _ := ethLayer.(*layers.Ethernet)
		info.SrcMAC = eth.SrcMAC.String()
		info.DstMAC = eth.DstMAC.String()
	}

	// 2. Parse Network Layer (IP Addresses)
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		info.SrcIP = ip.SrcIP.String()
		info.DstIP = ip.DstIP.String()
		info.Protocol = ip.Protocol.String()
	} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv6)
		info.SrcIP = ip.SrcIP.String()
		info.DstIP = ip.DstIP.String()
		info.Protocol = ip.NextHeader.String()
	}

	// 3. Parse Transport Layer (Ports)
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		info.SrcPort = int(tcp.SrcPort)
		info.DstPort = int(tcp.DstPort)
		info.Protocol = "TCP"
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		info.SrcPort = int(udp.SrcPort)
		info.DstPort = int(udp.DstPort)
		info.Protocol = "UDP"
	}

	// 4. Parse Application Layer (Payload)
	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		info.AppPayload = ExtractApplicationData(appLayer.Payload())
	}

	return info
}
