package cmd

import (
	"crypto/sha1"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/vinnterab/pgpkms/kms"
	"github.com/vinnterab/pgpkms/pgp"
)

// ListSecretKeys lists KMS signing keys in GPG-compatible format.
// If args contains a search term, only keys matching by UID, fingerprint, or key ID are shown.
func ListSecretKeys(client kms.Client, opts *Opts, args []string, sw *StatusWriter, lw *LoggerWriter) error {
	keys, err := client.ListKeys()
	if err != nil {
		return err
	}

	var filter string
	if len(args) > 0 {
		filter = args[0]
	}

	for _, key := range keys {
		info, err := pgp.GetKeyInfo(key)
		if err != nil {
			continue
		}

		uid := formatUID(key)
		fingerprint := fmt.Sprintf("%X", info.Fingerprint)
		keyIdHex := fmt.Sprintf("%X", info.KeyId)
		creationUnix := info.CreationTime.Unix()

		if filter != "" && !matchesKey(filter, uid, fingerprint, keyIdHex) {
			continue
		}

		if opts.WithColons {
			printColonFormat(key, info, uid, fingerprint, keyIdHex, creationUnix)
		} else {
			printHumanFormat(key, info, uid, fingerprint)
		}
	}

	return nil
}

func matchesKey(filter, uid, fingerprint, keyIdHex string) bool {
	if strings.Contains(uid, filter) {
		return true
	}
	if strings.EqualFold(fingerprint, filter) || strings.EqualFold(keyIdHex, filter) {
		return true
	}
	return false
}

func formatUID(key *kms.PublicKey) string {
	name := key.Tags[pgpNameTag]
	email := key.Tags[pgpEmailTag]

	if name == "" && email == "" {
		return fmt.Sprintf("AWS KMS Key <%s>", *key.Description.KeyMetadata.Arn)
	}

	if email != "" {
		return fmt.Sprintf("%s <%s>", name, email)
	}

	return name
}

func printHumanFormat(key *kms.PublicKey, info *pgp.KeyInfo, uid, fingerprint string) {
	algoName := algoName(key.Key.KeySpec)
	dateStr := info.CreationTime.Format("2006-01-02")

	fmt.Printf("sec   %s %s [SC]\n", algoName, dateStr)
	fmt.Printf("      %s\n", fingerprint)
	fmt.Printf("uid           [ultimate] %s\n", uid)
}

func printColonFormat(key *kms.PublicKey, info *pgp.KeyInfo, uid, fingerprint, keyIdHex string, creationUnix int64) {
	algoNum := pgpAlgoNumber(key.Key.KeySpec)

	// sec line
	fmt.Printf("sec:u:%d:%d:%s:%d:::u:::scSC:::+:::23::0:\n",
		info.BitLength, algoNum, keyIdHex, creationUnix)

	// fpr line
	fmt.Printf("fpr:::::::::%s:\n", fingerprint)

	// uid line - hash is SHA1 of the UID string
	uidHash := fmt.Sprintf("%X", sha1.Sum([]byte(uid)))
	fmt.Printf("uid:u::::%d::%s::%s::::::::::0:\n",
		creationUnix, uidHash, uid)
}

func pgpAlgoNumber(keySpec types.KeySpec) int {
	switch keySpec {
	case types.KeySpecRsa2048, types.KeySpecRsa3072, types.KeySpecRsa4096:
		return 1
	case types.KeySpecEccNistP256, types.KeySpecEccNistP384, types.KeySpecEccNistP521:
		return 19
	default:
		return 0
	}
}

func algoName(keySpec types.KeySpec) string {
	switch keySpec {
	case types.KeySpecRsa2048:
		return "rsa2048"
	case types.KeySpecRsa3072:
		return "rsa3072"
	case types.KeySpecRsa4096:
		return "rsa4096"
	case types.KeySpecEccNistP256:
		return "nistp256"
	case types.KeySpecEccNistP384:
		return "nistp384"
	case types.KeySpecEccNistP521:
		return "nistp521"
	default:
		return strings.ToLower(string(keySpec))
	}
}
