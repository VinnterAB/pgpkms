package pgp

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"crypto/ecdsa"
	"crypto/rsa"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/vinnterab/pgpkms/kms"
)

// KeyInfo contains PGP key metadata extracted from a KMS public key
type KeyInfo struct {
	Fingerprint  []byte
	KeyId        uint64
	PubKeyAlgo   packet.PublicKeyAlgorithm
	BitLength    uint16
	CreationTime time.Time
}

// GetKeyInfo extracts PGP key information from a KMS public key
func GetKeyInfo(publicKey *kms.PublicKey) (*KeyInfo, error) {
	cryptoPubKey, err := publicKey.CryptoPublicKey()
	if err != nil {
		return nil, err
	}

	creationDate, err := publicKey.PGPCreationTime()
	if err != nil {
		return nil, err
	}
	pgpPubKey, err := newPGPPublicKey(creationDate, cryptoPubKey)
	if err != nil {
		return nil, err
	}

	var bitLength uint16
	switch pk := cryptoPubKey.(type) {
	case *rsa.PublicKey:
		bitLength = uint16(pk.N.BitLen())
	case *ecdsa.PublicKey:
		bitLength = uint16(pk.Curve.Params().BitSize)
	}

	return &KeyInfo{
		Fingerprint:  pgpPubKey.Fingerprint,
		KeyId:        pgpPubKey.KeyId,
		PubKeyAlgo:   pgpPubKey.PubKeyAlgo,
		BitLength:    bitLength,
		CreationTime: creationDate,
	}, nil
}

func Export(kmsKey *kms.PublicKey, signer crypto.Signer, armored bool, name, comment, email string) (*bytes.Buffer, error) {
	pubKeyAny := signer.Public()

	creationDate, err := kmsKey.PGPCreationTime()
	if err != nil {
		return nil, err
	}
	pgpPubKey, err := newPGPPublicKey(creationDate, pubKeyAny)
	if err != nil {
		return nil, err
	}

	// Create a self-signature for the identity
	var userId *packet.UserId
	if name != "" || comment != "" || email != "" {
		userId = packet.NewUserId(name, comment, email)
	} else {
		// Default fallback - use KMS ARN as the name
		userId = packet.NewUserId(fmt.Sprintf("AWS KMS Key for %s", *kmsKey.Description.KeyMetadata.Arn), "", "")
	}

	entity := &openpgp.Entity{
		PrimaryKey: pgpPubKey,
		PrivateKey: &packet.PrivateKey{
			PublicKey:  *pgpPubKey,
			PrivateKey: signer,
		},
		Identities: make(map[string]*openpgp.Identity),
	}

	// Create the identity and sign it
	identity := &openpgp.Identity{
		UserId: userId,
		SelfSignature: &packet.Signature{
			SigType:      packet.SigTypePositiveCert,
			PubKeyAlgo:   pgpPubKey.PubKeyAlgo,
			Hash:         SigningHash(pubKeyAny, crypto.SHA256),
			CreationTime: creationDate,
			IssuerKeyId:  &pgpPubKey.KeyId,
		},
	}

	// Sign the user ID with the primary key
	err = identity.SelfSignature.SignUserId(userId.Id, pgpPubKey, entity.PrivateKey, signingConfig(identity.SelfSignature.Hash))
	if err != nil {
		return nil, fmt.Errorf("failed to sign user ID: %w", err)
	}

	// Entity.Serialize writes Identity.Signatures, not SelfSignature.
	identity.Signatures = []*packet.Signature{identity.SelfSignature}
	entity.Identities[userId.Name] = identity

	return serialize(entity, armored)
}

// SigningHash returns the hash to sign with for the given public key. AWS KMS
// supports exactly one hash per ECDSA key spec, SHA-256 for P-256, SHA-384 for
// P-384 and SHA-512 for P-521, so for ECDSA keys that hash is used regardless
// of the requested one. GnuPG also rejects ECDSA signatures made with a hash
// shorter than the curve order. RSA keys use the requested hash.
func SigningHash(pub crypto.PublicKey, requested crypto.Hash) crypto.Hash {
	pk, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return requested
	}
	switch bits := pk.Curve.Params().BitSize; {
	case bits > 384:
		return crypto.SHA512
	case bits > 256:
		return crypto.SHA384
	default:
		return crypto.SHA256
	}
}

// signingConfig disables the random salt notation that go-crypto adds to v4
// signatures by default. The salt length is only defined for SHA-2 and SHA-3,
// so it breaks SHA-1 signing, and leaving it out keeps signatures identical in
// structure to what pgpkms produced with golang.org/x/crypto/openpgp.
func signingConfig(hash crypto.Hash) *packet.Config {
	return &packet.Config{
		DefaultHash:                           hash,
		NonDeterministicSignaturesViaNotation: packet.BoolPointer(false),
	}
}

func newPGPPublicKey(creationDate time.Time, pub crypto.PublicKey) (*packet.PublicKey, error) {
	switch pk := pub.(type) {
	case *rsa.PublicKey:
		return packet.NewRSAPublicKey(creationDate, pk), nil
	case *ecdsa.PublicKey:
		return newECDSAPublicKey(creationDate, pk)
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", pub)
	}
}

// RFC 6637 section 11 curve OIDs, without the leading length octet.
var ecdsaCurveOIDs = map[string][]byte{
	"P-256": {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07},
	"P-384": {0x2B, 0x81, 0x04, 0x00, 0x22},
	"P-521": {0x2B, 0x81, 0x04, 0x00, 0x23},
}

// newECDSAPublicKey builds the OpenPGP key packet for a crypto/ecdsa key.
// packet.NewECDSAPublicKey in github.com/ProtonMail/go-crypto only accepts the
// library's own ECDSA type, which cannot be constructed from a crypto/ecdsa
// key outside the library, so the RFC 6637 key packet is encoded here and
// parsed back. This can be replaced by packet.NewSignerPrivateKey once
// go-crypto accepts crypto.Signer keys with a crypto/ecdsa public key.
func newECDSAPublicKey(creationDate time.Time, pub *ecdsa.PublicKey) (*packet.PublicKey, error) {
	oid, ok := ecdsaCurveOIDs[pub.Curve.Params().Name]
	if !ok {
		return nil, fmt.Errorf("unsupported ECDSA curve: %s", pub.Curve.Params().Name)
	}
	ecdhPub, err := pub.ECDH()
	if err != nil {
		return nil, fmt.Errorf("invalid ECDSA public key: %w", err)
	}
	// Uncompressed SEC 1 point: 0x04 || X || Y.
	point := ecdhPub.Bytes()

	var body bytes.Buffer
	body.WriteByte(4)
	_ = binary.Write(&body, binary.BigEndian, uint32(creationDate.Unix()))
	body.WriteByte(byte(packet.PubKeyAlgoECDSA))
	body.WriteByte(byte(len(oid)))
	body.Write(oid)
	// The MPI bit count; the 0x04 prefix contributes three significant bits.
	_ = binary.Write(&body, binary.BigEndian, uint16(8*(len(point)-1)+3))
	body.Write(point)

	var pkt bytes.Buffer
	pkt.WriteByte(0x99) // Old format public key packet with a two-octet length
	_ = binary.Write(&pkt, binary.BigEndian, uint16(body.Len()))
	pkt.Write(body.Bytes())

	p, err := packet.Read(&pkt)
	if err != nil {
		return nil, fmt.Errorf("failed to build ECDSA public key packet: %w", err)
	}
	pgpPubKey, ok := p.(*packet.PublicKey)
	if !ok {
		return nil, fmt.Errorf("unexpected packet type %T for ECDSA public key", p)
	}
	return pgpPubKey, nil
}

func serialize(entity *openpgp.Entity, armored bool) (*bytes.Buffer, error) {
	// Serialize the public key
	pubKeyBuffer := new(bytes.Buffer)
	err := entity.Serialize(pubKeyBuffer)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize PGP public key: %w", err)
	}

	if armored {
		armoredBuffer := new(bytes.Buffer)
		w, err := armor.Encode(armoredBuffer, openpgp.PublicKeyType, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create armor writer for public key: %w", err)
		}
		_, err = io.Copy(w, pubKeyBuffer)
		if err != nil {
			return nil, fmt.Errorf("failed to write public key to armor: %w", err)
		}
		if err := w.Close(); err != nil {
			return nil, fmt.Errorf("failed to close armor writer: %w", err)
		}
		return armoredBuffer, nil
	}

	return pubKeyBuffer, nil
}

// SignData signs data using the provided KMS key and signer
func SignData(kmsKey *kms.PublicKey, signer crypto.Signer, data []byte, clearSign, armor bool, digestHash crypto.Hash) ([]byte, error) {
	pubKeyAny := signer.Public()

	creationDate, err := kmsKey.PGPCreationTime()
	if err != nil {
		return nil, err
	}
	pgpPubKey, err := newPGPPublicKey(creationDate, pubKeyAny)
	if err != nil {
		return nil, err
	}

	pgpPrivateKey := &packet.PrivateKey{
		PublicKey:  *pgpPubKey,
		PrivateKey: signer,
	}
	digestHash = SigningHash(pubKeyAny, digestHash)

	if clearSign {
		return clearSignData(pgpPrivateKey, data, digestHash)
	}

	return detachedSignature(pgpPrivateKey, data, armor, digestHash)
}

func clearSignData(pgpPrivateKey *packet.PrivateKey, data []byte, digestHash crypto.Hash) ([]byte, error) {
	var signature bytes.Buffer
	writer, err := clearsign.Encode(&signature, pgpPrivateKey, signingConfig(digestHash))
	if err != nil {
		return nil, fmt.Errorf("failed to create clearsign Encoder %w", err)
	}
	if _, err = writer.Write(data); err != nil {
		cerr := writer.Close()
		return nil, errors.Join(fmt.Errorf("failed to write to clearsign encoder: %w", err), cerr)
	}

	if cerr := writer.Close(); cerr != nil {
		return nil, fmt.Errorf("failed to close clearsign encoder: %w", cerr)
	}
	return addArmorChecksum(signature.Bytes())
}

var signatureArmorStart = []byte("\n-----BEGIN " + openpgp.SignatureType + "-----")

// addArmorChecksum re-armors the signature block of a cleartext signed
// message with a CRC24 checksum. go-crypto's clearsign always omits it, and
// GnuPG fails with "no valid OpenPGP data found" when such a block also has
// no base64 padding, which happens for about half of all P-521 signatures.
func addArmorChecksum(signed []byte) ([]byte, error) {
	// The signature block comes last, and a dash-escaped message cannot
	// contain a line starting with dashes.
	idx := bytes.LastIndex(signed, signatureArmorStart)
	if idx < 0 {
		return nil, errors.New("no signature block in cleartext signed message")
	}
	idx++

	block, err := armor.Decode(bytes.NewReader(signed[idx:]))
	if err != nil {
		return nil, fmt.Errorf("failed to decode clearsign signature block: %w", err)
	}

	var out bytes.Buffer
	out.Write(signed[:idx])
	w, err := armor.Encode(&out, block.Type, block.Header)
	if err != nil {
		return nil, fmt.Errorf("failed to create armor writer for signature: %w", err)
	}
	if _, err := io.Copy(w, block.Body); err != nil {
		return nil, errors.Join(fmt.Errorf("failed to re-armor signature: %w", err), w.Close())
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("failed to close armor writer for signature: %w", err)
	}
	return out.Bytes(), nil
}

// detachedSignature signs at the packet level because openpgp.DetachSign
// only accepts entities whose self-signature carries the signing key flag,
// and the KMS key is used here without any user ID or self-signature.
func detachedSignature(pgpPrivateKey *packet.PrivateKey, data []byte, armored bool, digestHash crypto.Hash) ([]byte, error) {
	config := signingConfig(digestHash)
	sig := &packet.Signature{
		Version:      pgpPrivateKey.Version,
		SigType:      packet.SigTypeBinary,
		PubKeyAlgo:   pgpPrivateKey.PubKeyAlgo,
		Hash:         digestHash,
		CreationTime: time.Now(),
		IssuerKeyId:  &pgpPrivateKey.KeyId,
	}

	h, err := sig.PrepareSign(config)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare signature: %w", err)
	}
	h.Write(data)
	if err := sig.Sign(h, pgpPrivateKey, config); err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}

	var signature bytes.Buffer
	var w io.Writer = &signature
	var armorWriter io.WriteCloser
	if armored {
		armorWriter, err = armor.Encode(&signature, openpgp.SignatureType, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create armor writer for signature: %w", err)
		}
		w = armorWriter
	}
	if err := sig.Serialize(w); err != nil {
		return nil, fmt.Errorf("failed to serialize signature: %w", err)
	}
	if armorWriter != nil {
		if err := armorWriter.Close(); err != nil {
			return nil, fmt.Errorf("failed to close armor writer for signature: %w", err)
		}
	}

	return signature.Bytes(), nil
}
