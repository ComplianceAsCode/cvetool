package main

import (
	"fmt"

	"github.com/ComplianceAsCode/cvetool/catalog"
	"github.com/urfave/cli/v2"
)

var catalogCmd = &cli.Command{
	Name:   "catalog",
	Usage:  "generate an RHEL package catalog",
	Action: generateCatalog,
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "rhel-version",
			Usage: "RHEL version to catalog",
		},
		&cli.StringFlag{
			Name:  "arch",
			Usage: "package architecture to catalog",
		},
		&cli.StringSliceFlag{
			Name:  "repo-id",
			Usage: "repository ID to catalog (repeatable)",
		},
		&cli.PathFlag{
			Name:  "output",
			Usage: "path for the generated catalog database",
		},
		&cli.PathFlag{
			Name:  "repo-cpe-mapping-file",
			Usage: "local repository-to-CPE mapping file",
		},
		&cli.StringFlag{
			Name:  "repo-cpe-mapping-url",
			Usage: "URL of the repository-to-CPE mapping",
		},
		&cli.PathFlag{
			Name:  "dnf-path",
			Value: "dnf",
			Usage: "path to the dnf executable",
		},
	},
}

func generateCatalog(c *cli.Context) error {
	if err := catalog.Generate(c.Context, catalog.GenerateOptions{
		RHELVersion:   c.String("rhel-version"),
		Architecture:  c.String("arch"),
		RepositoryIDs: c.StringSlice("repo-id"),
		OutputPath:    c.Path("output"),
		MappingFile:   c.Path("repo-cpe-mapping-file"),
		MappingURL:    c.String("repo-cpe-mapping-url"),
		DNFPath:       c.Path("dnf-path"),
	}); err != nil {
		return fmt.Errorf("generate catalog: %w", err)
	}
	return nil
}
