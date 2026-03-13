package cmd

import (
	"fmt"
	"strings"

	"github.com/vinnterab/pgpkms/kms"
	"github.com/vinnterab/pgpkms/pgp"
)

// ResolveKeyId resolves a user-provided key identifier to a KMS key ARN.
// If the identifier looks like an ARN or UUID, it is returned as-is.
// Otherwise, keys are listed and matched by UID, fingerprint, or key ID.
func ResolveKeyId(client kms.Client, user string) (string, error) {
	if !looksLikeUID(user) {
		return user, nil
	}

	keys, err := client.ListKeys()
	if err != nil {
		return "", fmt.Errorf("failed to list keys for lookup: %w", err)
	}

	for _, key := range keys {
		uid := formatUID(key)
		if strings.Contains(uid, user) {
			return *key.Description.KeyMetadata.Arn, nil
		}

		info, err := pgp.GetKeyInfo(key)
		if err != nil {
			continue
		}
		fingerprint := fmt.Sprintf("%X", info.Fingerprint)
		keyIdHex := fmt.Sprintf("%X", info.KeyId)

		if strings.EqualFold(fingerprint, user) || strings.EqualFold(keyIdHex, user) {
			return *key.Description.KeyMetadata.Arn, nil
		}
	}

	return "", fmt.Errorf("no key found matching %q", user)
}

func looksLikeUID(s string) bool {
	return strings.ContainsAny(s, " <@")
}
