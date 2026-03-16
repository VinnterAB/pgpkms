package cmd

import (
	"fmt"

	"github.com/vinnterab/pgpkms/kms"
	"github.com/vinnterab/pgpkms/pgp"
)

func ExportKey(client kms.Client, opts *Opts, args []string, sw *StatusWriter, lw *LoggerWriter) error {
	if opts.ArmorAlias {
		opts.Armor = true
	}

	var name, comment, email string
	if opts.ExportName != nil {
		name = *opts.ExportName
	}
	if opts.ExportComment != nil {
		comment = *opts.ExportComment
	}
	if opts.ExportEmail != nil {
		email = *opts.ExportEmail
	}

	lw.Log("exporting key %s", opts.User)

	key, err := client.GetKey(opts.User)
	if err != nil {
		return err
	}

	// Log all Tags from Public Key
	for k, v := range key.PublicKey.Tags {
		lw.Log("key tag: %s=%s", k, v)
	}

	if name == "" && key.PublicKey.Tags[pgpNameTag] != "" {
		name = key.PublicKey.Tags[pgpNameTag]
	}
	if email == "" && key.PublicKey.Tags[pgpEmailTag] != "" {
		email = key.PublicKey.Tags[pgpEmailTag]
	}

	// Check that we have at least name or email
	if name == "" && email == "" {
		return fmt.Errorf("at least one of --export-name or --export-email must be provided")
	}

	info, err := pgp.GetKeyInfo(key.PublicKey)
	if err != nil {
		return err
	}
	fingerprint := fmt.Sprintf("%X", info.Fingerprint)
	sw.Emit("KEY_CONSIDERED", fingerprint, "0")

	bytes, err := pgp.Export(key.PublicKey, key.PrivateKey, opts.Armor, name, comment, email)
	if err != nil {
		return err
	}

	fmt.Println(bytes.String())

	return nil
}
