package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"

	flags "github.com/jessevdk/go-flags"
	"github.com/vinnterab/pgpkms/kms"
)

var opts Opts

func Usage() string {
	return "USAGE"
}

func replaceEqualSigns(helptext string) string {
	return strings.ReplaceAll(helptext, "=", " ")
}

func Execute(client kms.Client) error {
	parser := flags.NewParser(&opts, flags.Default&^flags.PrintErrors)

	args, err := parser.Parse()
	if err != nil {
		if flagsErr, ok := err.(*flags.Error); ok {
			if flagsErr.Type == flags.ErrHelp {
				// Print custom help without = characters
				help := flagsErr.Message
				help = replaceEqualSigns(help)
				fmt.Print(help)
				return nil
			}
		}
		fmt.Fprintf(os.Stderr, "%s", err)
		os.Exit(1)
	}

	if opts.ArmorAlias {
		opts.Armor = true
	}

	if opts.ClearSignAlias {
		opts.ClearSign = true
	}

	if opts.DetachedSign && opts.ClearSign {
		return errors.New("conflicting commands")
	}

	if opts.DetachedSign {
		opts.Sign = true
	}

	if opts.Export && (opts.Sign || opts.ClearSign) {
		return errors.New("conflicting commands")
	}

	// these require a key
	if (opts.Export || opts.Sign || opts.ClearSign) && opts.User == "" {
		return errors.New("Specify the key id with -u/--local-user ")
	}

	if opts.Export {
		fmt.Println("Will do export")
		return ExportKey(client, &opts, args)
	}

	if opts.Sign || opts.ClearSign {
		return Sign(client, &opts, args)
	}

	// No command provided, show usage
	var helpBuf strings.Builder
	parser.WriteHelp(&helpBuf)
	help := helpBuf.String()
	help = replaceEqualSigns(help)
	fmt.Print(help)
	return nil
}
