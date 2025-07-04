package cmd

type Opts struct {
	Armor          bool    `short:"a" long:"armor" description:"Use ASCII Armoured format for the output"`
	ArmorAlias     bool    `long:"armour" description:"Alias for --armor"`
	Export         bool    `long:"export" description:"Export a public part of a KMS key in a PGP Key Block"`
	ExportName     *string `long:"export-name" description:"Name to use for the exported PGP key (used with --export)"`
	ExportEmail    *string `long:"export-email" description:"Email to use for the exported PGP key (used with --export)"`
	ExportComment  *string `long:"export-comment" description:"Comment to use for the exported PGP key (used with --export)"`
	Sign           bool    `long:"sign" description:"Sign a file using KMS key"`
	ClearSign      bool    `long:"clear-sign" description:"Create a clear text signature using KMS key"`
	ClearSignAlias bool    `long:"clearsign"  description:"Alias for --clear-sign"`
	Output         *string `short:"o" long:"output" description:"Output file (default: input file + .asc)"`
	User           string  `short:"u" long:"local-user" description:"The key ID to use"`
}
