package database

import (
	"database/sql"
	"errors"
)

func (d *Database) GetChatOldestContiguousID(chatID int) (int, error) {
	row := d.db.QueryRow(`
		SELECT oldest_contiguous_id
		FROM chat_sync_states
		WHERE chat_id = ?
	`, chatID)

	var oldestContiguousID int

	if err := row.Scan(&oldestContiguousID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, nil
		}
		return 0, err
	}

	return oldestContiguousID, nil
}

func (d *Database) SetChatOldestContiguousID(chatID, oldestContiguousID int) error {
	_, err := d.db.Exec(`
		INSERT INTO chat_sync_states (chat_id, oldest_contiguous_id)
		VALUES (?, ?)
		ON CONFLICT(chat_id) DO UPDATE SET
			oldest_contiguous_id = excluded.oldest_contiguous_id
	`, chatID, oldestContiguousID)

	return err
}
