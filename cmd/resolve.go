package cmd

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/vinnterab/pgpkms/kms"
	"github.com/vinnterab/pgpkms/pgp"
)

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// ResolveKeyId resolves a user-provided key identifier to a KMS key ARN.
// If the identifier looks like a KMS identifier (ARN, alias, UUID), it is returned as-is.
// Otherwise, keys are listed and matched by UID, fingerprint, or key ID.
func ResolveKeyId(client kms.Client, user string) (string, error) {
	if looksLikeKMSIdentifier(user) {
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

// looksLikeKMSIdentifier returns true if the string looks like something
// KMS can resolve directly: an ARN, an alias, or a UUID.
func looksLikeKMSIdentifier(s string) bool {
	return strings.HasPrefix(s, "arn:") ||
		strings.HasPrefix(s, "alias/") ||
		uuidPattern.MatchString(s)
}
