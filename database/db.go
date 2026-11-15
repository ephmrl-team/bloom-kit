package database

import (
	"fmt"
	"path/filepath"

	sqlite "gosqlite.org"
	"gosqlite.org/vfs/crypto"
)

type Database struct {
	db *sqlite.DB
}

func NewDatabase(encryptionKey []byte, storagePath string) (*Database, error) {
	if len(encryptionKey) != 32 {
		return nil, fmt.Errorf("invalid encryption key")
	}

	dbPath := filepath.Join(storagePath, "bloom.db")

	db, err := crypto.Open(
		sqlite.Config{
			Path:    dbPath,
			Pragmas: sqlite.RecommendedPragmas(),
		},
		crypto.Options{
			Key: encryptionKey,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to open encrypted database: %w", err)
	}

	schema := `
	CREATE TABLE IF NOT EXISTS users (
	    id TEXT PRIMARY KEY,
	    username TEXT NOT NULL UNIQUE,
	    display_name TEXT,
	    description TEXT,
	    ml_kem_public_key TEXT NOT NULL,
	    ecdh_public_key TEXT NOT NULL,
	    ed_public_key TEXT NOT NULL,
	    date DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS chats (
	    id INTEGER PRIMARY KEY,
	    members TEXT NOT NULL,
	    handshake TEXT NOT NULL,
	    chat_key TEXT NOT NULL,
	    sync_key TEXT NOT NULL,
		created_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS messages (
	    id INTEGER PRIMARY KEY,
	    chat_id INTEGER NOT NULL,
	    author_id TEXT NOT NULL,
	    seen DATETIME,
	    reply_to INTEGER,
	    nonce TEXT NOT NULL,
	    content TEXT NOT NULL,
		created_at DATETIME NOT NULL,

	    FOREIGN KEY (chat_id) REFERENCES chats(id) ON DELETE CASCADE,
	    FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE CASCADE,
	    FOREIGN KEY (reply_to) REFERENCES messages(id) ON DELETE SET NULL
	);

	CREATE TABLE IF NOT EXISTS chat_sync_states (
	    chat_id INTEGER PRIMARY KEY,
	    oldest_contiguous_id INTEGER NOT NULL DEFAULT 0,
	    newest_contiguous_id INTEGER NOT NULL DEFAULT 0,

	    FOREIGN KEY (chat_id) REFERENCES chats(id) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS idx_messages_chat_id_id
	    ON messages(chat_id, id);

	CREATE INDEX IF NOT EXISTS idx_messages_author_id
	    ON messages(author_id);

	CREATE INDEX IF NOT EXISTS idx_messages_reply_to
	    ON messages(reply_to);

	CREATE INDEX IF NOT EXISTS idx_messages_seen
	    ON messages(seen);

	CREATE INDEX IF NOT EXISTS idx_messages_created_at
    	ON messages(created_at);
	`

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create schema: %w", err)
	}

	rows, err := db.Query(`
		SELECT 1
		FROM pragma_table_info('chat_sync_states')
		WHERE name = 'newest_contiguous_id'
	`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to inspect chat_sync_states schema: %w", err)
	}
	hasNewestContiguousID := rows.Next()
	rows.Close()

	if !hasNewestContiguousID {
		if _, err := db.Exec(`
			ALTER TABLE chat_sync_states
			ADD COLUMN newest_contiguous_id INTEGER NOT NULL DEFAULT 0
		`); err != nil {
			db.Close()
			return nil, fmt.Errorf("failed to add newest_contiguous_id: %w", err)
		}
	}

	return &Database{db: db}, nil
}

func (d *Database) ClearAll() error {
	if d == nil || d.db == nil {
		return fmt.Errorf("database is not initialized")
	}

	tx, err := d.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	for _, table := range []string{
		"messages",
		"chat_sync_states",
		"chats",
		"users",
	} {
		if _, err := tx.Exec("DELETE FROM " + table); err != nil {
			return fmt.Errorf("failed to clear %s: %w", table, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	if _, err := d.db.Exec("VACUUM"); err != nil {
		return fmt.Errorf("failed to vacuum database: %w", err)
	}

	return nil
}

func (d *Database) closeDatabase() {
	if d.db != nil {
		_ = d.db.Close()
	}
}
