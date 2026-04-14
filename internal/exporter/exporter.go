package exporter

// PacketInfo holds the normalized data extracted from a raw network packet.
type PacketInfo struct {
	Timestamp  string `json:"timestamp"`
	SrcMAC     string `json:"src_mac,omitempty"`
	DstMAC     string `json:"dst_mac,omitempty"`
	SrcIP      string `json:"src_ip,omitempty"`
	DstIP      string `json:"dst_ip,omitempty"`
	Protocol   string `json:"protocol"`
	SrcPort    int    `json:"src_port,omitempty"`
	DstPort    int    `json:"dst_port,omitempty"`
	Length     int    `json:"length"`
	AppPayload string `json:"app_payload,omitempty"`
}

// Exporter defines the interface for outputting packet data.
type Exporter interface {
	Export(packet PacketInfo) error
	Close() error
}
