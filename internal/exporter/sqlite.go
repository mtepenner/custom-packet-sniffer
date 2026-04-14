package exporter

import (
	"database/sql"
	"fmt"

	// Import the sqlite3 driver. The underscore means we import it for its side-effects 
	// (registering with the database/sql package) without calling it directly.
	_ "github.com/mattn/go-sqlite3"
)

// SQLiteExporter handles writing packet data into a local SQLite database.
type SQLiteExporter struct {
	db *sql.DB
}

// NewSQLiteExporter initializes the database connection and ensures the schema exists.
func NewSQLiteExporter(dbPath string) (*SQLiteExporter, error) {
	// Open the SQLite database file (it will be created if it doesn't exist)
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Create the packets table if this is a fresh database
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS packets (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp TEXT,
		src_mac TEXT,
		dst_mac TEXT,
		src_ip TEXT,
		dst_ip TEXT,
		protocol TEXT,
		src_port INTEGER,
		dst_port INTEGER,
		length INTEGER,
		app_payload TEXT
	);`

	_, err = db.Exec(createTableSQL)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create table schema: %w", err)
	}

	return &SQLiteExporter{db: db}, nil
}

// Export implements the Exporter interface, inserting a single packet into the database.
// The database/sql package handles connection pooling and thread safety for us automatically.
func (s *SQLiteExporter) Export(packet PacketInfo) error {
	insertSQL := `
	INSERT INTO packets (
		timestamp, src_mac, dst_mac, src_ip, dst_ip, 
		protocol, src_port, dst_port, length, app_payload
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := s.db.Exec(insertSQL,
		packet.Timestamp,
		packet.SrcMAC,
		packet.DstMAC,
		packet.SrcIP,
		packet.DstIP,
		packet.Protocol,
		packet.SrcPort,
		packet.DstPort,
		packet.Length,
		packet.AppPayload,
	)

	return err
}

// Close gracefully closes the database connection.
func (s *SQLiteExporter) Close() error {
	return s.db.Close()
}
