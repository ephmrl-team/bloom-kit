package mappers

import (
	"encoding/base64"
	"fmt"

	"github.com/slipe-fun/bloom-kit/domain"
	"github.com/slipe-fun/skid-v4/pkg/identity"
	"github.com/slipe-fun/skid-v4/pkg/messages"
)

func MapPublicKeys(mlKem768, x448, ed448 []byte) *domain.PublicKeys {
	return &domain.PublicKeys{
		MlKem768: base64.StdEncoding.EncodeToString(mlKem768),
		X448:     base64.StdEncoding.EncodeToString(x448),
		Ed448:    base64.StdEncoding.EncodeToString(ed448),
	}
}

func MapSecretKeys(secretKeys *identity.SecretKeys) (*[]byte, error) {
	if secretKeys == nil {
		return nil, domain.ErrNilSecretKeys
	}

	packSecretKeys, err := secretKeys.Pack()
	if err != nil {
		return nil, err
	}

	return &packSecretKeys, nil
}

func UnmapSecretKeys(mappedSecretKeys []byte) (*identity.SecretKeys, error) {
	return identity.Unpack(mappedSecretKeys)
}

func UnmapPublicKeys(publicKeys *domain.PublicKeys) (*identity.PublicKeys, error) {
	if publicKeys == nil {
		return nil, domain.ErrNilPublicKeys
	}

	mlKem768Bytes, err := base64.StdEncoding.DecodeString(publicKeys.MlKem768)
	if err != nil {
		return nil, err
	}

	x448Bytes, err := base64.StdEncoding.DecodeString(publicKeys.X448)
	if err != nil {
		return nil, err
	}

	ed448Bytes, err := base64.StdEncoding.DecodeString(publicKeys.Ed448)
	if err != nil {
		return nil, err
	}

	return &identity.PublicKeys{
		MlKem768: mlKem768Bytes,
		X448:     x448Bytes,
		Ed448:    ed448Bytes,
	}, nil
}

func ConvertUserToIdentity(user *domain.User) (*identity.User, error) {
	if user == nil {
		return nil, domain.ErrNilUser
	}

	if user.ID == "" {
		return nil, fmt.Errorf("%w: user ID is empty", domain.ErrIncompleteUser)
	}

	publicKeys, err := UnmapPublicKeys(&domain.PublicKeys{
		MlKem768: user.MlKemPublicKey,
		X448:     user.EcdhPublicKey,
		Ed448:    user.EdPublicKey,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to decode public keys for user %s: %w", user.ID, err)
	}

	if len(publicKeys.MlKem768) == 0 || len(publicKeys.X448) == 0 || len(publicKeys.Ed448) == 0 {
		return nil, fmt.Errorf("%w: user %s has empty public keys", domain.ErrIncompleteUser, user.ID)
	}

	return &identity.User{
		ID: user.ID,
		PublicKeys: identity.PublicKeys{
			MlKem768: publicKeys.MlKem768,
			X448:     publicKeys.X448,
			Ed448:    publicKeys.Ed448,
		},
	}, nil
}

func ConvertCredentialsToUser(creds *domain.SavedCredentials) (*identity.User, error) {
	if creds == nil {
		return nil, domain.ErrNotAuthenticated
	}

	if creds.UserID == "" {
		return nil, fmt.Errorf("%w: current user ID is empty", domain.ErrInvalidUserIdentity)
	}

	publicKeys, err := UnmapPublicKeys(&creds.PublicKeys)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode current user public keys: %w", domain.ErrInvalidUserIdentity, err)
	}

	if len(publicKeys.MlKem768) == 0 || len(publicKeys.X448) == 0 || len(publicKeys.Ed448) == 0 {
		return nil, fmt.Errorf("%w: current user has empty public keys", domain.ErrInvalidUserIdentity)
	}

	return &identity.User{
		ID:         creds.UserID,
		PublicKeys: *publicKeys,
	}, nil
}

func MapEncryptedGroupKey(encryptedGroupKey *messages.EncryptedMessage) *domain.EncryptedGroupKey {
	return &domain.EncryptedGroupKey{
		Ciphertext: base64.StdEncoding.EncodeToString(encryptedGroupKey.Ciphertext),
		Nonce:      base64.StdEncoding.EncodeToString(encryptedGroupKey.Nonce),
		Salt:       base64.StdEncoding.EncodeToString(encryptedGroupKey.Salt),
	}
}
