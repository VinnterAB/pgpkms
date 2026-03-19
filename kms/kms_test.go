package kms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"gotest.tools/v3/assert"
)

type mockKMSAPI struct {
	describeKeyFunc      func(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	getPublicKeyFunc     func(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	listKeysFunc         func(ctx context.Context, params *kms.ListKeysInput, optFns ...func(*kms.Options)) (*kms.ListKeysOutput, error)
	listResourceTagsFunc func(ctx context.Context, params *kms.ListResourceTagsInput, optFns ...func(*kms.Options)) (*kms.ListResourceTagsOutput, error)
	signFunc             func(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
}

func (m *mockKMSAPI) DescribeKey(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	if m.describeKeyFunc == nil {
		return nil, fmt.Errorf("unexpected DescribeKey call")
	}
	return m.describeKeyFunc(ctx, params, optFns...)
}

func (m *mockKMSAPI) GetPublicKey(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	if m.getPublicKeyFunc == nil {
		return nil, fmt.Errorf("unexpected GetPublicKey call")
	}
	return m.getPublicKeyFunc(ctx, params, optFns...)
}

func (m *mockKMSAPI) ListKeys(ctx context.Context, params *kms.ListKeysInput, optFns ...func(*kms.Options)) (*kms.ListKeysOutput, error) {
	if m.listKeysFunc == nil {
		return nil, fmt.Errorf("unexpected ListKeys call")
	}
	return m.listKeysFunc(ctx, params, optFns...)
}

func (m *mockKMSAPI) ListResourceTags(ctx context.Context, params *kms.ListResourceTagsInput, optFns ...func(*kms.Options)) (*kms.ListResourceTagsOutput, error) {
	if m.listResourceTagsFunc == nil {
		return nil, fmt.Errorf("unexpected ListResourceTags call")
	}
	return m.listResourceTagsFunc(ctx, params, optFns...)
}

func (m *mockKMSAPI) Sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
	if m.signFunc == nil {
		return nil, fmt.Errorf("unexpected Sign call")
	}
	return m.signFunc(ctx, params, optFns...)
}

// MockClient implements the Client interface for testing
type MockClient struct {
	getKeyFunc   func(keyId string) (*Key, error)
	listKeysFunc func() ([]*PublicKey, error)
}

func (m *MockClient) GetKey(keyId string) (*Key, error) {
	if m.getKeyFunc != nil {
		return m.getKeyFunc(keyId)
	}

	// Default implementation - create a mock key
	privateKey, pubKeyBytes, err := createTestECDSAKey()
	if err != nil {
		return nil, err
	}

	keyArn := "arn:aws:kms:us-east-1:123456789012:key/" + keyId
	creationDate := time.Now()

	publicKey := &PublicKey{
		Description: &kms.DescribeKeyOutput{
			KeyMetadata: &types.KeyMetadata{
				KeyId:        &keyId,
				Arn:          &keyArn,
				CreationDate: &creationDate,
			},
		},
		Key: &kms.GetPublicKeyOutput{
			KeyId:     &keyId,
			PublicKey: pubKeyBytes,
			KeySpec:   types.KeySpecEccNistP256,
		},
	}

	return &Key{
		PublicKey:  publicKey,
		PrivateKey: &TestSigner{privateKey: privateKey},
	}, nil
}

func (m *MockClient) ListKeys() ([]*PublicKey, error) {
	if m.listKeysFunc != nil {
		return m.listKeysFunc()
	}
	return nil, nil
}

// TestSigner implements crypto.Signer for testing
type TestSigner struct {
	privateKey *ecdsa.PrivateKey
}

func (s *TestSigner) Public() crypto.PublicKey {
	return &s.privateKey.PublicKey
}

func (s *TestSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.privateKey.Sign(rand, digest, opts)
}

// Helper function to create a valid ECDSA public key for testing
func createTestECDSAKey() (*ecdsa.PrivateKey, []byte, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	return privateKey, pubKeyBytes, nil
}

func TestNewAWSKmsClient(t *testing.T) {
	// Create a minimal AWS config for testing
	cfg := aws.Config{
		Region: "us-east-1",
	}

	client := NewAWSKmsClient(cfg)
	assert.Assert(t, client != nil, "Client should not be nil")
	assert.Assert(t, client.client != nil, "Underlying KMS client should not be nil")
}

func TestPublicKey_GetKeyId(t *testing.T) {
	keyId := "test-key-id-12345"
	publicKey := &PublicKey{
		Description: &kms.DescribeKeyOutput{
			KeyMetadata: &types.KeyMetadata{
				KeyId: &keyId,
			},
		},
	}

	result := publicKey.GetKeyId()
	assert.Equal(t, result, keyId)
}

func TestMockClient_GetKey_Success(t *testing.T) {
	testKeyId := "test-key-id"

	mockClient := &MockClient{}
	key, err := mockClient.GetKey(testKeyId)

	assert.NilError(t, err)
	assert.Assert(t, key != nil)
	assert.Assert(t, key.PublicKey != nil)
	assert.Assert(t, key.PrivateKey != nil)
	assert.Equal(t, key.PublicKey.GetKeyId(), testKeyId)
}

func TestMockClient_GetKey_Error(t *testing.T) {
	testKeyId := "test-key-id"

	mockClient := &MockClient{
		getKeyFunc: func(keyId string) (*Key, error) {
			return nil, fmt.Errorf("mock error: key not found")
		},
	}

	_, err := mockClient.GetKey(testKeyId)
	assert.ErrorContains(t, err, "mock error")
}

func TestAWSKmsClient_GetKey_FillsTags(t *testing.T) {
	keyID := "test-key-id"
	keyArn := "arn:aws:kms:us-east-1:123456789012:key/" + keyID
	creationDate := time.Now()
	_, pubKeyBytes, err := createTestECDSAKey()
	assert.NilError(t, err)

	client := &AWSKmsClient{
		client: &mockKMSAPI{
			describeKeyFunc: func(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
				assert.Equal(t, *params.KeyId, keyID)
				return &kms.DescribeKeyOutput{
					KeyMetadata: &types.KeyMetadata{
						KeyId:        &keyID,
						Arn:          &keyArn,
						CreationDate: &creationDate,
						Enabled:      true,
						KeyUsage:     types.KeyUsageTypeSignVerify,
						KeySpec:      types.KeySpecEccNistP256,
					},
				}, nil
			},
			getPublicKeyFunc: func(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
				assert.Equal(t, *params.KeyId, keyID)
				return &kms.GetPublicKeyOutput{
					KeyId:     &keyID,
					PublicKey: pubKeyBytes,
					KeySpec:   types.KeySpecEccNistP256,
				}, nil
			},
			listResourceTagsFunc: func(ctx context.Context, params *kms.ListResourceTagsInput, optFns ...func(*kms.Options)) (*kms.ListResourceTagsOutput, error) {
				assert.Equal(t, *params.KeyId, keyID)
				return &kms.ListResourceTagsOutput{
					Tags: []types.Tag{{TagKey: aws.String("env"), TagValue: aws.String("test")}},
				}, nil
			},
		},
	}

	key, err := client.GetKey(keyID)

	assert.NilError(t, err)
	assert.DeepEqual(t, key.PublicKey.Tags, map[string]string{"env": "test"})
}

func TestAWSKmsClient_ListKeys_FillsTags(t *testing.T) {
	keyID := "test-key-id"
	keyArn := "arn:aws:kms:us-east-1:123456789012:key/" + keyID
	creationDate := time.Now()
	_, pubKeyBytes, err := createTestECDSAKey()
	assert.NilError(t, err)

	client := &AWSKmsClient{
		client: &mockKMSAPI{
			listKeysFunc: func(ctx context.Context, params *kms.ListKeysInput, optFns ...func(*kms.Options)) (*kms.ListKeysOutput, error) {
				return &kms.ListKeysOutput{
					Keys: []types.KeyListEntry{{KeyId: &keyID}},
				}, nil
			},
			describeKeyFunc: func(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
				assert.Equal(t, *params.KeyId, keyID)
				return &kms.DescribeKeyOutput{
					KeyMetadata: &types.KeyMetadata{
						KeyId:        &keyID,
						Arn:          &keyArn,
						CreationDate: &creationDate,
						Enabled:      true,
						KeyUsage:     types.KeyUsageTypeSignVerify,
						KeySpec:      types.KeySpecEccNistP256,
					},
				}, nil
			},
			getPublicKeyFunc: func(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
				assert.Equal(t, *params.KeyId, keyID)
				return &kms.GetPublicKeyOutput{
					KeyId:     &keyID,
					PublicKey: pubKeyBytes,
					KeySpec:   types.KeySpecEccNistP256,
				}, nil
			},
			listResourceTagsFunc: func(ctx context.Context, params *kms.ListResourceTagsInput, optFns ...func(*kms.Options)) (*kms.ListResourceTagsOutput, error) {
				assert.Equal(t, *params.KeyId, keyID)
				return &kms.ListResourceTagsOutput{
					Tags: []types.Tag{{TagKey: aws.String("team"), TagValue: aws.String("infra")}},
				}, nil
			},
		},
	}

	keys, err := client.ListKeys()

	assert.NilError(t, err)
	assert.Equal(t, len(keys), 1)
	assert.DeepEqual(t, keys[0].Tags, map[string]string{"team": "infra"})
}

func TestPublicKey_PGPCreationTime_NoTag(t *testing.T) {
	keyId := "test-key-id"
	creationDate := time.Date(2025, 6, 15, 10, 0, 0, 0, time.UTC)
	publicKey := &PublicKey{
		Description: &kms.DescribeKeyOutput{
			KeyMetadata: &types.KeyMetadata{
				KeyId:        &keyId,
				CreationDate: &creationDate,
			},
		},
		Tags: map[string]string{},
	}

	result, err := publicKey.PGPCreationTime()
	assert.NilError(t, err)
	assert.Equal(t, result, creationDate)
}

func TestPublicKey_PGPCreationTime_NilTags(t *testing.T) {
	keyId := "test-key-id"
	creationDate := time.Date(2025, 6, 15, 10, 0, 0, 0, time.UTC)
	publicKey := &PublicKey{
		Description: &kms.DescribeKeyOutput{
			KeyMetadata: &types.KeyMetadata{
				KeyId:        &keyId,
				CreationDate: &creationDate,
			},
		},
	}

	result, err := publicKey.PGPCreationTime()
	assert.NilError(t, err)
	assert.Equal(t, result, creationDate)
}

func TestPublicKey_PGPCreationTime_ValidTag(t *testing.T) {
	keyId := "test-key-id"
	kmsCreationDate := time.Date(2025, 6, 15, 10, 0, 0, 0, time.UTC)
	originalCreation := time.Date(2020, 3, 1, 12, 0, 0, 0, time.UTC)
	publicKey := &PublicKey{
		Description: &kms.DescribeKeyOutput{
			KeyMetadata: &types.KeyMetadata{
				KeyId:        &keyId,
				CreationDate: &kmsCreationDate,
			},
		},
		Tags: map[string]string{
			"PGPCreationTime": originalCreation.Format(time.RFC3339),
		},
	}

	result, err := publicKey.PGPCreationTime()
	assert.NilError(t, err)
	assert.Equal(t, result, originalCreation)
}

func TestPublicKey_PGPCreationTime_MalformedTag(t *testing.T) {
	keyId := "test-key-id"
	creationDate := time.Date(2025, 6, 15, 10, 0, 0, 0, time.UTC)
	publicKey := &PublicKey{
		Description: &kms.DescribeKeyOutput{
			KeyMetadata: &types.KeyMetadata{
				KeyId:        &keyId,
				CreationDate: &creationDate,
			},
		},
		Tags: map[string]string{
			"PGPCreationTime": "not-a-date",
		},
	}

	_, err := publicKey.PGPCreationTime()
	assert.ErrorContains(t, err, "invalid PGPCreationTime tag value")
}

func TestKMSSigner_Public(t *testing.T) {
	// Create test key data
	privateKey, pubKeyBytes, err := createTestECDSAKey()
	assert.NilError(t, err)

	publicKey := &PublicKey{
		Key: &kms.GetPublicKeyOutput{
			PublicKey: pubKeyBytes,
			KeySpec:   types.KeySpecEccNistP256,
		},
	}

	signer := &KMSSigner{
		keyId:     "test-key",
		publicKey: publicKey,
	}

	pubKey := signer.Public()
	assert.Assert(t, pubKey != nil)

	// Verify it's the same public key
	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	assert.Assert(t, ok, "Public key should be ECDSA")
	assert.Assert(t, ecdsaPubKey.Equal(&privateKey.PublicKey), "Public keys should match")
}

func TestKMSSigner_Public_InvalidKey(t *testing.T) {
	publicKey := &PublicKey{
		Key: &kms.GetPublicKeyOutput{
			PublicKey: []byte("invalid key data"),
			KeySpec:   types.KeySpecEccNistP256,
		},
	}

	signer := &KMSSigner{
		keyId:     "test-key",
		publicKey: publicKey,
	}

	// This should panic due to invalid key data
	defer func() {
		if r := recover(); r != nil {
			// Panic occurred as expected
		} else {
			t.Error("Expected panic did not occur")
		}
	}()
	signer.Public()
}
