package cmd

import (
	"fmt"

	"github.com/vinnterab/pgpkms/kms"
	"github.com/vinnterab/pgpkms/pgp"
)

func ExportKey(client kms.Client, opts *Opts, args []string) error {
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

	// Check that we have at least name or email
	if name == "" && email == "" {
		return fmt.Errorf("at least one of --export-name or --export-email must be provided")
	}

	key, err := client.GetKey(*opts.Export)
	if err != nil {
		return err
	}

	bytes, err := pgp.Export(key.PublicKey, key.PrivateKey, opts.Armor, name, comment, email)
	if err != nil {
		return err
	}

	fmt.Println(bytes.String())

	return nil
}
