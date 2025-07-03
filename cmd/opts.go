package cmd

type Opts struct {
	Armor         bool    `short:"a" long:"armor" description:"Use ASCII Armoured format for the output"`
	Export        *string `long:"export" description:"Export a public part of a KMS key in a PGP Key Block"`
	ExportName    *string `long:"export-name" description:"Name to use for the exported PGP key (used with --export)"`
	ExportEmail   *string `long:"export-email" description:"Email to use for the exported PGP key (used with --export)"`
	ExportComment *string `long:"export-comment" description:"Comment to use for the exported PGP key (used with --export)"`
	Sign          *string `long:"sign" description:"Sign a file using KMS key (specify KMS key ID)"`
	ClearSign     *string `long:"clear-sign" description:"Create a clear text signature using KMS key (specify KMS key ID)"`
	Output        *string `short:"o" long:"output" description:"Output file (default: input file + .asc)"`
}
