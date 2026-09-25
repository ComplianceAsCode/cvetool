package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ComplianceAsCode/cvetool/catalog"
	"github.com/quay/zlog"
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
	options, err := resolveCatalogInputsAtRoot(c.Context, catalog.GenerateOptions{
		RHELVersion:   c.String("rhel-version"),
		Architecture:  c.String("arch"),
		RepositoryIDs: c.StringSlice("repo-id"),
		OutputPath:    c.Path("output"),
		MappingFile:   c.Path("repo-cpe-mapping-file"),
		MappingURL:    c.String("repo-cpe-mapping-url"),
		DNFPath:       c.Path("dnf-path"),
	}, "/")
	if err != nil {
		return fmt.Errorf("resolve catalog inputs: %w", err)
	}
	if err := catalog.Generate(c.Context, options); err != nil {
		return fmt.Errorf("generate catalog: %w", err)
	}
	return nil
}

func resolveCatalogInputsAtRoot(ctx context.Context, options catalog.GenerateOptions, hostRoot string) (catalog.GenerateOptions, error) {
	if options.OutputPath == "" {
		return catalog.GenerateOptions{}, fmt.Errorf("catalog output path is required")
	}
	root, err := filepath.Abs(hostRoot)
	if err != nil {
		return catalog.GenerateOptions{}, fmt.Errorf("resolve host root: %w", err)
	}

	dnfPath := options.DNFPath
	if dnfPath == "" {
		dnfPath = "dnf"
	}
	options.DNFPath = dnfPath

	var architectures catalog.ArchitectureSet
	if len(options.DNF.Architectures) != 0 {
		architectures, err = catalog.ResolveTargetArchitecture(options.DNF.Architectures)
	} else {
		var installed []string
		installed, err = catalog.QueryInstalledRPMArchitectures(ctx, options.CommandRunner, "rpm", root)
		if err == nil {
			architectures, err = catalog.ResolveTargetArchitecture(installed)
		}
	}
	if err != nil {
		return catalog.GenerateOptions{}, fmt.Errorf("resolve host architecture: %w", err)
	}
	if options.Architecture == "" {
		options.Architecture = architectures.Primary
	}
	if options.Architecture == architectures.Primary {
		options.DNF.Architectures = architectures.Packages
	} else {
		requestedArchitecture, err := catalog.ResolveTargetArchitecture([]string{options.Architecture})
		if err != nil {
			return catalog.GenerateOptions{}, fmt.Errorf("resolve requested architecture: %w", err)
		}
		options.DNF.Architectures = requestedArchitecture.Packages
	}
	if options.RHELVersion == "" {
		osRelease, err := os.ReadFile(filepath.Join(root, "etc", "os-release"))
		if err != nil {
			return catalog.GenerateOptions{}, fmt.Errorf("read host os-release: %w", err)
		}
		targetInfo, err := catalog.ResolveTargetInfo(osRelease, "", architectures)
		if err != nil {
			return catalog.GenerateOptions{}, fmt.Errorf("resolve host RHEL version: %w", err)
		}
		options.RHELVersion = targetInfo.RHELVersion
	}

	if len(options.RepositoryIDs) == 0 {
		enabled, err := catalog.EnabledHostRepositories(ctx, options.CommandRunner, dnfPath)
		if err != nil {
			return catalog.GenerateOptions{}, err
		}
		mapping, err := catalog.LoadRepositoryMapping(ctx, options.MappingFile, options.MappingURL)
		if err != nil {
			return catalog.GenerateOptions{}, err
		}
		selection, selectionErr := catalog.SelectMappedRepositories(mapping, enabled)
		for _, id := range selection.Skipped {
			zlog.Warn(ctx).Str("repository_id", id).Msg("skipping enabled repository without a CPE mapping")
		}
		if selectionErr != nil {
			return catalog.GenerateOptions{}, selectionErr
		}
		options.RepositoryIDs = selection.Mapped
	}
	return options, nil
}
