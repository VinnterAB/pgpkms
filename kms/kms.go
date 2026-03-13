package kms

import (
	"context"
	"crypto"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// Client defines the interface for KMS operations
type Client interface {
	GetKey(keyId string) (*Key, error)
	ListKeys() ([]*PublicKey, error)
}

type kmsAPI interface {
	DescribeKey(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	GetPublicKey(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	ListKeys(ctx context.Context, params *kms.ListKeysInput, optFns ...func(*kms.Options)) (*kms.ListKeysOutput, error)
	ListResourceTags(ctx context.Context, params *kms.ListResourceTagsInput, optFns ...func(*kms.Options)) (*kms.ListResourceTagsOutput, error)
	Sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
}

// AWSKmsClient implements Client using AWS KMS
type AWSKmsClient struct {
	client kmsAPI
}

func (c *AWSKmsClient) getKeyTags(ctx context.Context, keyId string) map[string]string {
	tags := make(map[string]string)
	tagsOutput, err := c.client.ListResourceTags(ctx, &kms.ListResourceTagsInput{KeyId: &keyId})
	if err != nil {
		return tags
	}

	for _, tag := range tagsOutput.Tags {
		tags[*tag.TagKey] = *tag.TagValue
	}

	return tags
}

// NewAWSKmsClient creates a new AWS KMS client
func NewAWSKmsClient(cfg aws.Config) *AWSKmsClient {
	client := kms.NewFromConfig(cfg)
	return &AWSKmsClient{client: client}
}

// GetKey retrieves a KMS key and returns both public and private key components
func (c *AWSKmsClient) GetKey(keyId string) (*Key, error) {
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

	publicKey := &PublicKey{
		Description: keyDescription,
		Key:         pubkey,
		Tags:        c.getKeyTags(ctx, keyId),
	}

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

// ListKeys lists all KMS signing keys with their tags
func (c *AWSKmsClient) ListKeys() ([]*PublicKey, error) {
	ctx := context.Background()
	var result []*PublicKey

	paginator := kms.NewListKeysPaginator(c.client, &kms.ListKeysInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list KMS keys: %w", err)
		}

		for _, keyEntry := range page.Keys {
			keyId := *keyEntry.KeyId

			desc, err := c.client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: &keyId})
			if err != nil {
				continue
			}

			meta := desc.KeyMetadata
			if !meta.Enabled || meta.KeyUsage != types.KeyUsageTypeSignVerify || meta.KeySpec == types.KeySpecSymmetricDefault {
				continue
			}

			pubkey, err := c.client.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: &keyId})
			if err != nil {
				continue
			}

			result = append(result, &PublicKey{
				Description: desc,
				Key:         pubkey,
				Tags:        c.getKeyTags(ctx, keyId),
			})
		}
	}

	return result, nil
}

// KMSSigner implements crypto.Signer for AWS KMS keys
type KMSSigner struct {
	keyId     string
	client    kmsAPI
	publicKey *PublicKey
}

// Public returns the public key
func (s *KMSSigner) Public() crypto.PublicKey {
	pubKeyAny, err := s.publicKey.CryptoPublicKey()
	if err != nil {
		panic(err)
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
