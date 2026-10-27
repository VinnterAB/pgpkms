package pgp

import (
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	kmslib "github.com/vinnterab/pgpkms/kms"
	"gotest.tools/v3/assert"
)

// The expected values were produced by golang.org/x/crypto/openpgp. Keys
// already exported by pgpkms must keep their fingerprints when the OpenPGP
// implementation changes.
func TestGetKeyInfo_StableFingerprints(t *testing.T) {
	creationDate := time.Date(2024, 5, 17, 9, 30, 0, 0, time.UTC)
	keyId := "test-key-id"
	keyArn := "arn:aws:kms:us-east-1:123456789012:key/test-key-id"

	tests := []struct {
		name        string
		keySpec     types.KeySpec
		pkix        string
		fingerprint string
		keyId       string
	}{
		{
			name:        "RSA 2048",
			keySpec:     types.KeySpecRsa2048,
			pkix:        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnjMgjpDK2dA76KkGP+maPAdEjH7TTD55jtqvoAxJvD7OIxlCgAGBBK3Z7i1pBKBtDjerMLjdAkjztkrCrq8WvQv+mYZrPBHkMjTV0cURNBhOHYvwOgY8FV2xICqbJ+cvZyk/3XxMww1XIutOSUpUOxB81lkdh1KAufPb0fd+7EhLpA5HLcZzv+3PhgRHGhhkbIkUnhg5akhZTiIZD5XdjHu7pTifC/zisVhe9Kscxqtjd0UUPxAcxONsaXUDCEz6RmHOgsmOtPi2e8dJr7hXoSXZqxRddBjB/1liNovWI/DEXRdZEvd0ZkAuxF9eMxipoR44+GHN+4MUSWMoSZjWEQIDAQAB",
			fingerprint: "68FA83AC0D9B6CC7E7EDACFAE79031041D88A81C",
			keyId:       "E79031041D88A81C",
		},
		{
			name:        "ECC NIST P256",
			keySpec:     types.KeySpecEccNistP256,
			pkix:        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMy+B4UK5SG8rBJA0BYBJw+G8+edXHMVKPw1TTecHds1c2GUfMXA6XB9Bq8Y4U7VfGrMDVQKzH7jDkiM8TIJ7mA==",
			fingerprint: "9956F6A5620D1C4D751BAD31C39E8B625E74E9A6",
			keyId:       "C39E8B625E74E9A6",
		},
		{
			name:        "ECC NIST P384",
			keySpec:     types.KeySpecEccNistP384,
			pkix:        "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEgqj2UahFRzEWBX73xTh2fGwDkkIcQFQHxjJ0POrQEJ3PlEWAqFahjGW3JVzM9VL5UJB/ySG2A5O/G5HmJbyKVHyF0pFWLnZEgINel+3aZW9n6jj0AvF5cav6+oEPRjj2",
			fingerprint: "76952AA89EF9E86CC7A2529E304AF705FB8F27E7",
			keyId:       "304AF705FB8F27E7",
		},
		{
			name:        "ECC NIST P521",
			keySpec:     types.KeySpecEccNistP521,
			pkix:        "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAVf3FUc8zZV6CTuUWQhpgEPH6bK48yeSdph1/zOapxnOZK81RLUe0TwIhY7FpFgAEpL9yCLb1p1KWzRGXF/Dil84AOJE04s1pnc7wErfvoj+oxtU15ITYHVZTieVHJxvXBiTD6c7OqY7Vn2ChMRrwvuoX/jXvPCH7vGOnSgg1uXaLDUA=",
			fingerprint: "1C504636A680A0334389DD9CD5C68BF3592A9680",
			keyId:       "D5C68BF3592A9680",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			der, err := base64.StdEncoding.DecodeString(tc.pkix)
			assert.NilError(t, err)

			info, err := GetKeyInfo(&kmslib.PublicKey{
				Description: &kms.DescribeKeyOutput{
					KeyMetadata: &types.KeyMetadata{
						KeyId:        &keyId,
						Arn:          &keyArn,
						CreationDate: &creationDate,
					},
				},
				Key: &kms.GetPublicKeyOutput{
					KeyId:     &keyId,
					PublicKey: der,
					KeySpec:   tc.keySpec,
				},
			})
			assert.NilError(t, err)
			assert.Equal(t, fmt.Sprintf("%X", info.Fingerprint), tc.fingerprint)
			assert.Equal(t, fmt.Sprintf("%016X", info.KeyId), tc.keyId)
		})
	}
}
