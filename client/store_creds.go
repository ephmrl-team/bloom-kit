package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/slipe-fun/bloom-kit/crypto"
	"github.com/slipe-fun/bloom-kit/domain"
)

func (c *BloomClient) saveCredentials(creds *domain.SavedCredentials) error {
	if creds == nil {
		return errors.New("credentials are nil")
	}

	plainText, err := json.Marshal(creds)
	if err != nil {
		return err
	}
	defer crypto.Zero(plainText)

	if len(c.encryptionKey) != 32 {
		return errors.New("invalid encryption key")
	}

	ciphertext, err := crypto.Encrypt(c.encryptionKey, plainText, nil)
	if err != nil {
		return err
	}

	filePath := filepath.Join(c.storagePath, "session.dat")
	err = os.WriteFile(filePath, ciphertext, 0600)
	if err != nil {
		return err
	}

	crypto.Zero(creds.RawRecoveryKey)
	crypto.Zero(creds.MasterKey)
	crypto.Zero(creds.SecretKeys)

	c.credentialsMu.Lock()
	c.credentials = creds
	c.credentialsMu.Unlock()

	return nil
}

func (c *BloomClient) getCredentials() (*domain.SavedCredentials, error) {
	c.credentialsMu.RLock()
	creds := c.credentials
	c.credentialsMu.RUnlock()

	if creds == nil {
		return nil, domain.ErrNotAuthenticated
	}

	return creds, nil
}

func (c *BloomClient) loadCredentials() (*domain.SavedCredentials, error) {
	filePath := filepath.Join(c.storagePath, "session.dat")

	ciphertext, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	if len(c.encryptionKey) != 32 {
		return nil, errors.New("invalid encryption key")
	}

	plainText, err := crypto.Decrypt(c.encryptionKey, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	defer crypto.Zero(plainText)

	var creds domain.SavedCredentials
	err = json.Unmarshal(plainText, &creds)
	if err != nil {
		return nil, err
	}

	c.credentialsMu.Lock()
	c.credentials = &domain.SavedCredentials{
		UserID: creds.UserID,
		PublicKeys: domain.PublicKeys{
			MlKem768: creds.PublicKeys.MlKem768,
			X448:     creds.PublicKeys.X448,
			Ed448:    creds.PublicKeys.Ed448,
		},
		UserJSON: creds.UserJSON,
		Token:    creds.Token,
	}
	c.credentialsMu.Unlock()

	return &creds, nil
}

func (c *BloomClient) UpdateCredentialsUserJSON(userJSON []byte) error {
	creds, err := c.loadCredentials()
	if err != nil {
		return err
	}

	creds.UserJSON = userJSON

	if err := c.saveCredentials(creds); err != nil {
		return err
	}

	return nil
}

func (c *BloomClient) ClearCredentials() {
	c.CancelExchange()
	c.stopWebSocket()
	c.StopChatsSync()

	var clearErrs []error

	filePath := filepath.Join(c.storagePath, "session.dat")
	if err := os.Remove(filePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		clearErrs = append(clearErrs, fmt.Errorf("failed to remove session file: %w", err))
	}

	c.credentialsMu.Lock()
	c.credentials = nil
	c.credentialsMu.Unlock()

	c.apiClient.SetToken("")
	c.updateUser(nil)

	if c.database != nil {
		if err := c.database.ClearAll(); err != nil {
			clearErrs = append(clearErrs, fmt.Errorf("failed to clear database: %w", err))
		}
	}

	if len(clearErrs) > 0 {
		c.reportBackgroundError(errors.Join(clearErrs...))
	}
}
