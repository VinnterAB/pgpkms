package pgp

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/vinnterab/pgpkms/kms"
)

// Export generates a PGP public key from a KMS RSA key and crypto.Signer.
func Export(kmsKey *kms.PublicKey, signer crypto.Signer, armored bool, name, comment, email string) (*bytes.Buffer, error) {
	pubKeyAny := signer.Public()

	creationDate := kmsKey.Description.KeyMetadata.CreationDate

	rsaPub, ok := pubKeyAny.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("unsupported key type: only RSA is supported with ProtonMail openpgp")
	}

	pgpPubKey := packet.NewRSAPublicKey(*creationDate, rsaPub)

	// Create user ID
	var userId *packet.UserId
	if name != "" || comment != "" || email != "" {
		userId = packet.NewUserId(name, comment, email)
	} else {
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

	// Create and sign identity
	identity := &openpgp.Identity{
		UserId: userId,
		SelfSignature: &packet.Signature{
			SigType:      packet.SigTypePositiveCert,
			PubKeyAlgo:   pgpPubKey.PubKeyAlgo,
			Hash:         crypto.SHA256,
			CreationTime: *creationDate,
			IssuerKeyId:  &pgpPubKey.KeyId,
		},
	}

	err := identity.SelfSignature.SignUserId(userId.Id, pgpPubKey, entity.PrivateKey, &packet.Config{
		DefaultHash: crypto.SHA256,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to sign user ID: %w", err)
	}

	entity.Identities[userId.Name] = identity
	return serialize(entity, armored)
}

// serialize writes the PGP entity to a buffer, optionally armored.
func serialize(entity *openpgp.Entity, armored bool) (*bytes.Buffer, error) {
	buf := new(bytes.Buffer)
	if err := entity.Serialize(buf); err != nil {
		return nil, fmt.Errorf("failed to serialize PGP public key: %w", err)
	}

	if armored {
		armoredBuf := new(bytes.Buffer)
		w, err := armor.Encode(armoredBuf, openpgp.PublicKeyType, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create armor writer: %w", err)
		}
		if _, err := io.Copy(w, buf); err != nil {
			return nil, fmt.Errorf("failed to write to armor: %w", err)
		}
		if err := w.Close(); err != nil {
			return nil, fmt.Errorf("failed to close armor writer: %w", err)
		}
		return armoredBuf, nil
	}

	return buf, nil
}

// SignData signs data using the provided KMS RSA key and signer
func SignData(kmsKey *kms.PublicKey, signer crypto.Signer, data []byte, clearSign, armor bool, digestHash crypto.Hash) ([]byte, error) {
	pubKeyAny := signer.Public()
	rsaPub, ok := pubKeyAny.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("unsupported key type: only RSA is supported with ProtonMail openpgp")
	}

	pgpPubKey := packet.NewRSAPublicKey(*kmsKey.Description.KeyMetadata.CreationDate, rsaPub)

	pgpPrivateKey := &packet.PrivateKey{
		PublicKey:  *pgpPubKey,
		PrivateKey: signer,
	}

	if clearSign {
		return clearSignData(pgpPrivateKey, data, digestHash)
	}
	return detachedSignature(pgpPrivateKey, data, armor, digestHash)
}

// clearSignData creates a cleartext signature
func clearSignData(pgpPrivateKey *packet.PrivateKey, data []byte, digestHash crypto.Hash) ([]byte, error) {
	var sig bytes.Buffer
	w, err := clearsign.Encode(&sig, pgpPrivateKey, &packet.Config{DefaultHash: digestHash})
	if err != nil {
		return nil, fmt.Errorf("failed to create clearsign encoder: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		cerr := w.Close()
		return nil, errors.Join(fmt.Errorf("failed to write to clearsign encoder: %w", err), cerr)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("failed to close clearsign encoder: %w", err)
	}
	return sig.Bytes(), nil
}

// detachedSignature creates a detached signature
func detachedSignature(pgpPrivateKey *packet.PrivateKey, data []byte, armor bool, digestHash crypto.Hash) ([]byte, error) {
	entity := &openpgp.Entity{
		PrimaryKey: &pgpPrivateKey.PublicKey,
		PrivateKey: pgpPrivateKey,
	}

	var sig bytes.Buffer
	var err error
	if armor {
		err = openpgp.ArmoredDetachSign(&sig, entity, bytes.NewReader(data), &packet.Config{
			DefaultHash: digestHash,
		})
	} else {
		err = openpgp.DetachSign(&sig, entity, bytes.NewReader(data), &packet.Config{
			DefaultHash: digestHash,
		})
	}
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}
	return sig.Bytes(), nil
}
