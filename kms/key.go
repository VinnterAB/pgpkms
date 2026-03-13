package kms

import (
	"crypto"
	"crypto/x509"
	"fmt"

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

// Key represents a KMS key with both public and private key components
type Key struct {
	PublicKey  *PublicKey
	PrivateKey crypto.Signer
}
