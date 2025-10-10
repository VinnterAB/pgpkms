package pgp

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"io"

	"crypto/ecdsa"
	"crypto/rsa"

	"github.com/vinnterab/pgpkms/kms"
	//nolint:staticcheck // SA1019: required for OpenPGP interoperability; planned migration later
	"golang.org/x/crypto/openpgp"
	//nolint:staticcheck // SA1019: required for OpenPGP interoperability
	"golang.org/x/crypto/openpgp/armor"
	//nolint:staticcheck // SA1019: required for OpenPGP interoperability
	"golang.org/x/crypto/openpgp/clearsign"
	//nolint:staticcheck // SA1019: required for OpenPGP interoperability
	"golang.org/x/crypto/openpgp/packet"
)

func Export(kmsKey *kms.PublicKey, signer crypto.Signer, armored bool, name, comment, email string) (*bytes.Buffer, error) {
	pubKeyAny := signer.Public()

	creationDate := kmsKey.Description.KeyMetadata.CreationDate
	var pgpPubKey *packet.PublicKey
	switch pk := pubKeyAny.(type) {
	case *rsa.PublicKey:
		pgpPubKey = packet.NewRSAPublicKey(*creationDate, pk)
	case *ecdsa.PublicKey:
		pgpPubKey = packet.NewECDSAPublicKey(*creationDate, pk)
	default:
		return nil, fmt.Errorf("unsupported public key type from KMS: %T", pubKeyAny)
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
			Hash:         crypto.SHA256,
			CreationTime: *creationDate,
			IssuerKeyId:  &pgpPubKey.KeyId,
		},
	}

	// Sign the user ID with the primary key
	err := identity.SelfSignature.SignUserId(userId.Id, pgpPubKey, entity.PrivateKey, &packet.Config{
		DefaultHash: crypto.SHA256,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to sign user ID: %w", err)
	}

	entity.Identities[userId.Name] = identity

	return serialize(entity, armored)
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

	creationDate := kmsKey.Description.KeyMetadata.CreationDate
	var pgpPubKey *packet.PublicKey
	switch pk := pubKeyAny.(type) {
	case *rsa.PublicKey:
		pgpPubKey = packet.NewRSAPublicKey(*creationDate, pk)
	case *ecdsa.PublicKey:
		pgpPubKey = packet.NewECDSAPublicKey(*creationDate, pk)
	default:
		return nil, fmt.Errorf("unsupported public key type from KMS: %T", pubKeyAny)
	}

	pgpPrivateKey := &packet.PrivateKey{
		PublicKey:  *pgpPubKey,
		PrivateKey: signer,
	}

	if clearSign {
		return clearSignData(pgpPrivateKey, data, digestHash)
	}

	return detachedSignature(pgpPrivateKey, data, armor, digestHash)
}

func clearSignData(pgpPrivateKey *packet.PrivateKey, data []byte, digestHash crypto.Hash) ([]byte, error) {
	var signature bytes.Buffer
	writer, err := clearsign.Encode(&signature, pgpPrivateKey, &packet.Config{
		DefaultHash: digestHash,
	})
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
	return signature.Bytes(), nil
}

func detachedSignature(pgpPrivateKey *packet.PrivateKey, data []byte, armor bool, digestHash crypto.Hash) ([]byte, error) {
	entity := &openpgp.Entity{
		PrimaryKey: &pgpPrivateKey.PublicKey,
		PrivateKey: pgpPrivateKey,
	}

	var err error
	var signature bytes.Buffer
	if armor {
		err = openpgp.ArmoredDetachSign(&signature, entity, bytes.NewReader(data), &packet.Config{
			DefaultHash: digestHash,
		})
	} else {
		err = openpgp.DetachSign(&signature, entity, bytes.NewReader(data), &packet.Config{
			DefaultHash: digestHash,
		})
	}

	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}

	return signature.Bytes(), nil
}
