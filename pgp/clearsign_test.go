package pgp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"io"
	"regexp"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	kmslib "github.com/vinnterab/pgpkms/kms"
	"gotest.tools/v3/assert"
)

// A P-521 signature of 186 bytes, so its base64 encoding has no padding.
// Without an armor checksum GnuPG fails to parse this signature block.
const unpaddedClearsigned = `-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

interop test payload

-----BEGIN PGP SIGNATURE-----

wrgEARMKACcFgmrgfuoJENXGi/NZKpaAFiEEHFBGNqaAoDNDid2c1caL81kqloAA
AMKBAgjtDRRQbM90V/ZNDY5wxAO1E8laxd/syJrsf38eGvAzO5qk3BcCK/7HJ+pk
ObMo8Cb5iIb+xjndOpujBzPgDegGoAIJAcFQKmPu9FmOPxzknIxY6otbdWUBvaS+
c4d8zMoKBK9rtpOUzpOYUJgpMTFeLdARe+ODJLr6SRCqr9LWRVUx8VlZ
-----END PGP SIGNATURE-----`

var armorChecksumLine = regexp.MustCompile(`\n=[A-Za-z0-9+/]{4}\n-----END PGP SIGNATURE-----$`)

func TestAddArmorChecksum(t *testing.T) {
	out, err := addArmorChecksum([]byte(unpaddedClearsigned))
	assert.NilError(t, err)
	assert.Assert(t, armorChecksumLine.Match(out), "missing armor checksum:\n%s", out)

	before, _ := clearsign.Decode([]byte(unpaddedClearsigned))
	after, rest := clearsign.Decode(out)
	assert.Assert(t, after != nil, "re-armored message does not decode")
	assert.Equal(t, len(rest), 0)
	assert.DeepEqual(t, after.Plaintext, before.Plaintext)
	assert.DeepEqual(t, readArmoredBody(t, after), readArmoredBody(t, before))
}

func TestAddArmorChecksumWithoutSignature(t *testing.T) {
	_, err := addArmorChecksum([]byte("no signature here"))
	assert.ErrorContains(t, err, "no signature block")
}

func TestClearSignP521HasArmorChecksum(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	assert.NilError(t, err)
	kmsKey := newTestKMSPublicKey(t, &priv.PublicKey)
	data := []byte("line one\n-----BEGIN PGP SIGNATURE-----\nline three\n")

	// P-521 signatures vary in length, so repeat to cover encodings with and
	// without base64 padding.
	for range 20 {
		out, err := SignData(kmsKey, priv, data, true, false, crypto.SHA512)
		assert.NilError(t, err)
		assert.Assert(t, armorChecksumLine.Match(out), "missing armor checksum:\n%s", out)

		block, rest := clearsign.Decode(out)
		assert.Assert(t, block != nil, "clearsigned message does not decode")
		assert.Equal(t, len(rest), 0)
		assert.DeepEqual(t, block.Plaintext, data)
	}
}

func readArmoredBody(t *testing.T, block *clearsign.Block) []byte {
	t.Helper()
	assert.Assert(t, block != nil)
	body, err := io.ReadAll(block.ArmoredSignature.Body)
	assert.NilError(t, err)
	return body
}

func newTestKMSPublicKey(t *testing.T, pub crypto.PublicKey) *kmslib.PublicKey {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	assert.NilError(t, err)
	keyId := "test-key-id"
	keyArn := "arn:aws:kms:us-east-1:123456789012:key/test-key-id"
	creationDate := time.Date(2024, 5, 17, 9, 30, 0, 0, time.UTC)
	return &kmslib.PublicKey{
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
		},
	}
}
