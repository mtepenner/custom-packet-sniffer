package exporter

import (
	"encoding/json"
	"os"
	"sync"
)

type JSONExporter struct {
	file *os.File
	mu   sync.Mutex
}

func NewJSONExporter(filename string) (*JSONExporter, error) {
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	return &JSONExporter{file: f}, nil
}

func (j *JSONExporter) Export(packet PacketInfo) error {
	j.mu.Lock()
	defer j.mu.Unlock()

	data, err := json.Marshal(packet)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = j.file.Write(data)
	return err
}

func (j *JSONExporter) Close() error {
	return j.file.Close()
}
