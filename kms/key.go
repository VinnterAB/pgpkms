package kms

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

type PublicKey struct {
	Description *kms.DescribeKeyOutput
	Key         *kms.GetPublicKeyOutput
	Tags        map[string]string
}

// CryptoPublicKey parses and returns the crypto.PublicKey from the PKIX-encoded key bytes
func (pk *PublicKey) CryptoPublicKey() (crypto.PublicKey, error) {
	pubKey, err := x509.ParsePKIXPublicKey(pk.Key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}
	return pubKey, nil
}

// GetKeyId returns the KMS key ID
func (pk *PublicKey) GetKeyId() string {
	return *pk.Description.KeyMetadata.KeyId
}

// PGPCreationTime returns the PGP key creation time.
// If the PGPCreationTime tag is set, it is parsed as RFC 3339 and returned.
// If the tag is malformed, an error is returned.
// Otherwise, it falls back to the KMS KeyMetadata.CreationDate.
func (pk *PublicKey) PGPCreationTime() (time.Time, error) {
	if raw, ok := pk.Tags["PGPCreationTime"]; ok {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return time.Time{}, fmt.Errorf("invalid %s tag value %q: %w", "PGPCreationTime", raw, err)
		}
		return t, nil
	}
	return *pk.Description.KeyMetadata.CreationDate, nil
}

// Key represents a KMS key with both public and private key components
type Key struct {
	PublicKey  *PublicKey
	PrivateKey crypto.Signer
}
