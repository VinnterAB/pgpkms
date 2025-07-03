package kms

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// Client defines the interface for KMS operations
type Client interface {
	GetKey(keyId string) (*Key, error)
}

// AWSKmsClient implements Client using AWS KMS
type AWSKmsClient struct {
	client *kms.Client
}

// NewAWSKmsClient creates a new AWS KMS client
func NewAWSKmsClient(cfg aws.Config) *AWSKmsClient {
	client := kms.NewFromConfig(cfg)
	return &AWSKmsClient{client: client}
}

// GetKey retrieves a KMS key and returns both public and private key components
func (c *AWSKmsClient) GetKey(keyId string) (*Key, error) {
	fmt.Printf("Exporting %s\n", keyId)

	ctx := context.Background()
	keyDescription, err := c.client.DescribeKey(ctx, &kms.DescribeKeyInput{
		KeyId: &keyId,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe KMS key %s: %w", keyId, err)
	}

	if keyDescription.KeyMetadata.KeyUsage != types.KeyUsageTypeSignVerify {
		return nil, fmt.Errorf("KMS key %s is not for signing (KeyUsage is %s)", keyId, keyDescription.KeyMetadata.KeyUsage)
	}
	if keyDescription.KeyMetadata.KeySpec == types.KeySpecSymmetricDefault {
		return nil, fmt.Errorf("KMS key %s is a symmetric key, not suitable for PGP signing", keyId)
	}

	pubkey, err := c.client.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: &keyId,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get public key for KMS key %s: %w", keyId, err)
	}

	publicKey := &PublicKey{Description: keyDescription, Key: pubkey}

	// Create KMS signer
	signer := &KMSSigner{
		keyId:     keyId,
		client:    c.client,
		publicKey: publicKey,
	}

	return &Key{
		PublicKey:  publicKey,
		PrivateKey: signer,
	}, nil
}

// KMSSigner implements crypto.Signer for AWS KMS keys
type KMSSigner struct {
	keyId     string
	client    *kms.Client
	publicKey *PublicKey
}

// Public returns the public key
func (s *KMSSigner) Public() crypto.PublicKey {
	// Parse the public key from the KMS key data
	pubKeyAny, err := x509.ParsePKIXPublicKey(s.publicKey.Key.PublicKey)
	if err != nil {
		panic(fmt.Sprintf("failed to parse public key: %v", err))
	}
	return pubKeyAny
}

// Sign signs the digest using AWS KMS
func (s *KMSSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	ctx := context.Background()

	// Determine the signing algorithm based on the KeySpec and hash
	var signingAlgorithm types.SigningAlgorithmSpec
	keySpec := s.publicKey.Key.KeySpec

	switch keySpec {
	case types.KeySpecEccNistP256, types.KeySpecEccNistP384, types.KeySpecEccNistP521, types.KeySpecEccSecgP256k1:
		// For ECDSA keys
		if opts.HashFunc() == crypto.SHA256 {
			signingAlgorithm = types.SigningAlgorithmSpecEcdsaSha256
		} else if opts.HashFunc() == crypto.SHA384 {
			signingAlgorithm = types.SigningAlgorithmSpecEcdsaSha384
		} else if opts.HashFunc() == crypto.SHA512 {
			signingAlgorithm = types.SigningAlgorithmSpecEcdsaSha512
		} else {
			return nil, fmt.Errorf("unsupported hash function for ECDSA: %v", opts.HashFunc())
		}
	case types.KeySpecRsa2048, types.KeySpecRsa3072, types.KeySpecRsa4096:
		// For RSA keys
		if opts.HashFunc() == crypto.SHA256 {
			signingAlgorithm = types.SigningAlgorithmSpecRsassaPkcs1V15Sha256
		} else if opts.HashFunc() == crypto.SHA384 {
			signingAlgorithm = types.SigningAlgorithmSpecRsassaPkcs1V15Sha384
		} else if opts.HashFunc() == crypto.SHA512 {
			signingAlgorithm = types.SigningAlgorithmSpecRsassaPkcs1V15Sha512
		} else {
			return nil, fmt.Errorf("unsupported hash function for RSA: %v", opts.HashFunc())
		}
	default:
		return nil, fmt.Errorf("unsupported key spec: %v", keySpec)
	}

	// Sign the digest
	result, err := s.client.Sign(ctx, &kms.SignInput{
		KeyId:            &s.keyId,
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: signingAlgorithm,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to sign with KMS: %w", err)
	}

	return result.Signature, nil
}

// Example of how to create a mock for testing:
//
// type MockClient struct{}
//
// func (m *MockClient) GetKey(keyId string) (*Key, error) {
//     // Return mock data
//     return &Key{
//         PublicKey: &PublicKey{...},
//         PrivateKey: &MockSigner{...},
//     }, nil
// }
//
// In tests, you can pass the mock to cmd.Execute:
// mockClient := &MockClient{}
// err := cmd.Execute(mockClient)
