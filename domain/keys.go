package domain

type EncryptedKey struct {
	Version    string `json:"version"`
	Ciphertext string `db:"ciphertext" json:"ciphertext"`
	Nonce      string `db:"nonce" json:"nonce"`
	Salt       string `db:"salt" json:"salt"`
	Signature  string `db:"signature" json:"signature"`
}

type IdentityPublicKeys struct {
	MlKemPublicKey string `json:"ml_kem768_public_key"`
	EcdhPublicKey  string `json:"x448_public_key"`
	EdPublicKey    string `json:"ed448_public_key"`
}

type EncryptedKeys struct {
	EncryptedKey
	ID     int    `db:"id" json:"id"`
	Type   string `db:"type" json:"type"`
	UserID string `db:"user_id" json:"user_id"`
}

type IdentityKeysRequest struct {
	EncryptedSecretKeys EncryptedKey       `json:"encrypted_secret_keys"`
	IdentityPublicKeys  IdentityPublicKeys `json:"public_keys"`
}

type GetKeysResponse struct {
	UserID int `json:"user_id"`
	EncryptedKey
}
