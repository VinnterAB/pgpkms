package kms

import (
	"crypto"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

type PublicKey struct {
	Description *kms.DescribeKeyOutput
	Key         *kms.GetPublicKeyOutput
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
