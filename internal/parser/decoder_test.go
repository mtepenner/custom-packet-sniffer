package parser

import (
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// buildEthernetIPv4TCPPacket constructs a minimal raw Ethernet+IPv4+TCP packet.
func buildEthernetIPv4TCPPacket(payload []byte) gopacket.Packet {
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       []byte{0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    []byte{192, 168, 1, 1},
		DstIP:    []byte{10, 0, 0, 1},
	}
	tcp := &layers.TCP{
		SrcPort: 12345,
		DstPort: 80,
		SYN:     true,
	}
	_ = tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	_ = gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(payload))

	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	// Set a known timestamp via metadata
	pkt.Metadata().Timestamp = time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	pkt.Metadata().Length = len(buf.Bytes())
	return pkt
}

// buildEthernetIPv4UDPPacket constructs a minimal Ethernet+IPv4+UDP packet.
func buildEthernetIPv4UDPPacket() gopacket.Packet {
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
		DstMAC:       []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    []byte{172, 16, 0, 1},
		DstIP:    []byte{172, 16, 0, 2},
	}
	udp := &layers.UDP{
		SrcPort: 5353,
		DstPort: 53,
	}
	_ = udp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	_ = gopacket.SerializeLayers(buf, opts, eth, ip, udp)

	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	pkt.Metadata().Length = len(buf.Bytes())
	return pkt
}

// buildEthernetIPv6TCPPacket constructs a minimal Ethernet+IPv6+TCP packet.
func buildEthernetIPv6TCPPacket() gopacket.Packet {
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       []byte{0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB},
		EthernetType: layers.EthernetTypeIPv6,
	}
	ip := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolTCP,
		SrcIP:      []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		DstIP:      []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
	}
	tcp := &layers.TCP{
		SrcPort: 44444,
		DstPort: 443,
		SYN:     true,
	}
	_ = tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	_ = gopacket.SerializeLayers(buf, opts, eth, ip, tcp)

	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	pkt.Metadata().Length = len(buf.Bytes())
	return pkt
}

func TestDecodePacket_IPv4TCP(t *testing.T) {
	pkt := buildEthernetIPv4TCPPacket(nil)
	info := DecodePacket(pkt)

	if info.SrcMAC != "00:11:22:33:44:55" {
		t.Errorf("unexpected SrcMAC: %s", info.SrcMAC)
	}
	if info.DstMAC != "66:77:88:99:aa:bb" {
		t.Errorf("unexpected DstMAC: %s", info.DstMAC)
	}
	if info.SrcIP != "192.168.1.1" {
		t.Errorf("unexpected SrcIP: %s", info.SrcIP)
	}
	if info.DstIP != "10.0.0.1" {
		t.Errorf("unexpected DstIP: %s", info.DstIP)
	}
	if info.Protocol != "TCP" {
		t.Errorf("unexpected Protocol: %s", info.Protocol)
	}
	if info.SrcPort != 12345 {
		t.Errorf("unexpected SrcPort: %d", info.SrcPort)
	}
	if info.DstPort != 80 {
		t.Errorf("unexpected DstPort: %d", info.DstPort)
	}
	if info.Length <= 0 {
		t.Errorf("expected positive Length, got %d", info.Length)
	}
}

func TestDecodePacket_IPv4UDP(t *testing.T) {
	pkt := buildEthernetIPv4UDPPacket()
	info := DecodePacket(pkt)

	if info.SrcIP != "172.16.0.1" {
		t.Errorf("unexpected SrcIP: %s", info.SrcIP)
	}
	if info.DstIP != "172.16.0.2" {
		t.Errorf("unexpected DstIP: %s", info.DstIP)
	}
	if info.Protocol != "UDP" {
		t.Errorf("unexpected Protocol: %s", info.Protocol)
	}
	if info.SrcPort != 5353 {
		t.Errorf("unexpected SrcPort: %d", info.SrcPort)
	}
	if info.DstPort != 53 {
		t.Errorf("unexpected DstPort: %d", info.DstPort)
	}
}

func TestDecodePacket_IPv6TCP(t *testing.T) {
	pkt := buildEthernetIPv6TCPPacket()
	info := DecodePacket(pkt)

	if info.SrcIP != "2001:db8::1" {
		t.Errorf("unexpected SrcIP: %s", info.SrcIP)
	}
	if info.DstIP != "2001:db8::2" {
		t.Errorf("unexpected DstIP: %s", info.DstIP)
	}
	if info.Protocol != "TCP" {
		t.Errorf("unexpected Protocol: %s", info.Protocol)
	}
	if info.DstPort != 443 {
		t.Errorf("unexpected DstPort: %d", info.DstPort)
	}
}

func TestDecodePacket_TimestampFromPacketMetadata(t *testing.T) {
	pkt := buildEthernetIPv4TCPPacket(nil)
	info := DecodePacket(pkt)

	// Timestamp should reflect the packet metadata time (2024-01-15T12:00:00Z)
	if info.Timestamp != "2024-01-15T12:00:00Z" {
		t.Errorf("expected packet metadata timestamp, got %q", info.Timestamp)
	}
}

func TestDecodePacket_TimestampFallsBackToNow(t *testing.T) {
	// When metadata timestamp is zero, DecodePacket should fall back to time.Now()
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       []byte{0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB},
		EthernetType: layers.EthernetTypeIPv4,
	}
	buf := gopacket.NewSerializeBuffer()
	_ = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, eth)
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	// Metadata timestamp is zero by default

	before := time.Now().UTC()
	info := DecodePacket(pkt)
	after := time.Now().UTC()

	ts, err := time.Parse(time.RFC3339Nano, info.Timestamp)
	if err != nil {
		t.Fatalf("failed to parse timestamp %q: %v", info.Timestamp, err)
	}
	if ts.Before(before) || ts.After(after) {
		t.Errorf("fallback timestamp %v is outside expected range [%v, %v]", ts, before, after)
	}
}

func TestDecodePacket_ApplicationPayload(t *testing.T) {
	payload := []byte("GET / HTTP/1.1\r\nHost: test.com\r\n\r\n")
	pkt := buildEthernetIPv4TCPPacket(payload)
	info := DecodePacket(pkt)

	if info.AppPayload != "GET / HTTP/1.1" {
		t.Errorf("unexpected AppPayload: %q", info.AppPayload)
	}
}
