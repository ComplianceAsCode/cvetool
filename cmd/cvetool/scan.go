package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/ComplianceAsCode/cvetool/catalog"
	"github.com/quay/claircore"
	"github.com/quay/claircore/enricher/cvss"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/libindex"
	"github.com/quay/claircore/libvuln"
	"github.com/quay/claircore/libvuln/driver"
	_ "github.com/quay/claircore/matchers/defaults"
	"github.com/quay/claircore/pkg/tarfs"
	"github.com/quay/claircore/rhel"
	"github.com/quay/zlog"
	"github.com/urfave/cli/v2"

	datastore "github.com/ComplianceAsCode/cvetool/datastore"
	ds_sqlite "github.com/ComplianceAsCode/cvetool/datastore/sqlite"
	image "github.com/ComplianceAsCode/cvetool/image"
	output "github.com/ComplianceAsCode/cvetool/output"
	"github.com/ComplianceAsCode/cvetool/util"
)

type EnumValue struct {
	Enum     []string
	Default  string
	selected string
}

func getDefaultDBPath() (string, error) {
	homeFolder, err := os.UserHomeDir()
	if err != nil || homeFolder == "" {
		return "", fmt.Errorf("home folder not set, DB path must be specified")
	}
	return filepath.Join(homeFolder, ".local", "share", "cvetool", "matcher.db"), nil
}

func (e *EnumValue) Set(value string) error {
	if slices.Contains(e.Enum, value) {
		e.selected = value
		return nil
	}

	return fmt.Errorf("allowed values are %s", strings.Join(e.Enum, ", "))
}

func (e EnumValue) String() string {
	if e.selected == "" {
		return e.Default
	}
	return e.selected
}

const (
	clairFmt = "clair"
	sarifFmt = "sarif"
	quayFmt  = "quay"
	plainFmt = "plain"
)

var scanCmd = &cli.Command{
	Name:    "scan",
	Aliases: []string{"s"},
	Usage:   "scan a system",
	Action:  scan,
	Flags: []cli.Flag{
		&cli.PathFlag{
			Name:    "root-path",
			Value:   "/",
			Usage:   "where to look for the local filesystem root",
			EnvVars: []string{"ROOT_PATH"},
		},
		&cli.PathFlag{
			Name:    "image-path",
			Value:   "",
			Usage:   "where to look for the saved image tar",
			EnvVars: []string{"IMAGE_PATH"},
		},
		&cli.PathFlag{
			Name:    "db-path",
			Value:   "",
			Usage:   "where to look for the matcher DB",
			EnvVars: []string{"DB_PATH"},
		},
		&cli.PathFlag{
			Name:  "catalog",
			Usage: "path to an offline RHEL package catalog",
		},
		&cli.GenericFlag{
			Name:    "format",
			Aliases: []string{"f"},
			Value: &EnumValue{
				Enum:    []string{clairFmt, sarifFmt, quayFmt, plainFmt},
				Default: plainFmt,
			},
			Usage:   "what output format the results should be in",
			EnvVars: []string{"FORMAT"},
		},
		&cli.IntFlag{
			Name:    "return-code",
			Aliases: []string{"c"},
			Value:   0,
			Usage:   "what status code to return when vulnerabilites are found",
			EnvVars: []string{"RETURN_CODE"},
		},
	},
}

func scan(c *cli.Context) (scanErr error) {
	ctx := c.Context

	var (
		// All arguments
		rootPath        = c.String("root-path")
		imgRef          = c.String("image-ref")
		imgPath         = c.String("image-path")
		dbPath          = c.String("db-path")
		dbURL           = c.String("db-url")
		catalogPath     = c.Path("catalog")
		format          = c.String("format")
		returnCode      = c.Int("return-code")
		dockerConfigDir = c.String("docker-config-dir")
	)

	var (
		mf *claircore.Manifest
		fa indexer.FetchArena
	)
	switch {
	case imgRef != "":
		cl := http.DefaultClient
		fa = libindex.NewRemoteFetchArena(cl, os.TempDir())
		err := os.Setenv("DOCKER_CONFIG", dockerConfigDir)
		if err != nil {
			return fmt.Errorf("error setting DOCKER_CONFIG env var")
		}
		mf, err = image.ManifestFromRemote(ctx, imgRef)
		if err != nil {
			return fmt.Errorf("error getting image information: %v", err)
		}
	case imgPath != "":
		fa = &LocalFetchArena{}
		var err error
		mf, err = image.ManifestFromLocal(ctx, imgPath)
		if err != nil {
			return fmt.Errorf("error getting image information: %v", err)
		}
	case rootPath != "":
		fa = &LocalFetchArena{}
		var err error
		mf, err = image.ManifestFromFilesystem(ctx, rootPath)
		if err != nil {
			return fmt.Errorf("error getting filesystem information: %v", err)
		}
	default:
		return fmt.Errorf("no --image-path ($IMAGE_PATH), --image-ref ($IMAGE_REF) or --root-path ($ROOT_PATH) set")
	}
	defer func() {
		for _, l := range mf.Layers {
			l.Close()
		}
	}()

	switch {
	case dbPath != "":
	case dbURL != "":
		var err error
		err = util.DownloadDB(ctx, dbURL, "")
		if err != nil {
			return fmt.Errorf("could not download database: %v", err)
		}
	default:
		var err error
		dbPath, err = getDefaultDBPath()
		if err != nil {
			return err
		}
	}

	if _, err := os.Stat(dbPath); err != nil {
		return fmt.Errorf("unable to get database path")
	}

	matcherStore, err := ds_sqlite.NewSQLiteMatcherStore(dbPath, true)
	if err != nil {
		return fmt.Errorf("error creating sqlite backend: %v", err)
	}
	cl := &http.Client{
		Timeout: 10 * time.Second,
	}

	matcherOpts := &libvuln.Options{
		Client:                   cl,
		Store:                    matcherStore,
		Locker:                   NewLocalLockSource(),
		DisableBackgroundUpdates: true,
		UpdateWorkers:            1,
		MatcherNames:             []string{"rhel"},
		// TODO: Do we actually need updaters for the report operation?
		// UpdaterSets:              []string{"rhel-vex", "cvss"},
		UpdaterSets: []string{},
		Enrichers: []driver.Enricher{
			&cvss.Enricher{},
		},
	}
	lv, err := libvuln.New(ctx, matcherOpts)
	if err != nil {
		return fmt.Errorf("error creating Libvuln: %v", err)
	}

	indexerOpts := &libindex.Options{
		Store:  datastore.NewLocalIndexerStore(),
		Locker: NewLocalLockSource(),
		// Limit indexers to RHEL ecosystem
		Ecosystems: []*indexer.Ecosystem{
			rhel.NewEcosystem(ctx),
		},
		FetchArena: fa,
	}
	preparedCatalog, err := prepareScanCatalogForSource(ctx, scanCatalogOptions{
		ExplicitPath: catalogPath,
		TargetRoot:   rootPath,
		DNF:          catalog.DNFOptions{Path: "dnf"},
	}, imgPath, imgRef)
	if err != nil {
		return fmt.Errorf("error preparing scan catalog: %w", err)
	}
	if preparedCatalog != nil {
		defer func() { scanErr = closeScanCatalog(scanErr, preparedCatalog) }()
		if err := preparedCatalog.configureScanner(indexerOpts); err != nil {
			return fmt.Errorf("error configuring scan catalog: %w", err)
		}
	}
	li, err := libindex.New(ctx, indexerOpts, http.DefaultClient)
	if err != nil {
		return fmt.Errorf("error creating Libindex: %v", err)
	}
	ir, err := li.Index(ctx, mf)
	// TODO (crozzy) Better error handling once claircore
	// error overhaul is merged.
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, fs.ErrInvalid):
		zlog.Warn(ctx).Err(err).Msg("inaccessible file or directory (invalid)")
	case errors.Is(err, fs.ErrPermission):
		zlog.Warn(ctx).Err(err).Msg("inaccessible file or directory (permission)")
	case errors.Is(err, tarfs.ErrFormat):
		return fmt.Errorf("error creating index report due to invalid layer: %v", err)
	default:
		return fmt.Errorf("error creating index report: %v", err)
	}
	var vr *claircore.VulnerabilityReport
	var catalogReader catalog.Reader
	if preparedCatalog != nil {
		catalogReader = preparedCatalog.Reader
	}
	err = scanWithCatalogValidation(ctx, catalogReader, ir, func() error {
		var err error
		vr, err = lv.Scan(ctx, ir)
		return err
	})
	if err != nil {
		return fmt.Errorf("error creating vulnerability report: %v", err)
	}

	switch format {
	case sarifFmt:
		tw, err := output.NewSarifWriter(os.Stdout)
		if err != nil {
			return fmt.Errorf("error creating sarif report writer: %v", err)
		}
		err = tw.Write(vr)
		if err != nil {
			return fmt.Errorf("error writing sarif report: %v", err)
		}
	case plainFmt:
		tw, err := output.NewPlainWriter(os.Stdout)
		if err != nil {
			return fmt.Errorf("error creating plain report writer: %v", err)
		}
		err = tw.Write(vr)
		if err != nil {
			return fmt.Errorf("error writing plain report: %v", err)
		}
	case quayFmt:
		quayReport, err := output.ReportToSecScan(vr)
		if err != nil {
			return fmt.Errorf("error creating quay format report: %v", err)
		}
		b, err := json.MarshalIndent(quayReport, "", "  ")
		if err != nil {
			return fmt.Errorf("could not marshal quay report: %v", err)
		}
		fmt.Println(string(b))
	default:
		b, err := json.MarshalIndent(vr, "", "  ")
		if err != nil {
			return fmt.Errorf("could not marshal vulnerability report: %v", err)
		}
		fmt.Println(string(b))
	}
	if preparedCatalog == nil {
		if advice := catalogAdvice(len(vr.Vulnerabilities), catalogPath); advice != "" {
			zlog.Warn(ctx).Msg(advice)
		}
	}

	if len(vr.Vulnerabilities) > 0 {
		return cli.Exit(nil, returnCode)
	}
	return nil
}

func catalogAdvice(vulnerabilityCount int, catalogPath string) string {
	if vulnerabilityCount > 0 || catalogPath != "" {
		return ""
	}
	return "No vulnerabilities found. For improved RHEL coverage, download a package catalog with `cvetool catalog` and rerun the scan with `--catalog <path>`."
}

func scanWithCatalogValidation(ctx context.Context, reader catalog.Reader, report *claircore.IndexReport, scan func() error) error {
	if reader != nil {
		metadata, err := reader.Metadata(ctx)
		if err != nil {
			return fmt.Errorf("error reading catalog metadata: %v", err)
		}
		if err := validateCatalogMetadata(metadata, report); err != nil {
			return err
		}
		diagnostics, err := catalog.EnrichIndexReport(ctx, report, reader)
		if err != nil {
			return fmt.Errorf("error enriching index report from catalog: %v", err)
		}
		zlog.Info(ctx).
			Int("packages_inspected", diagnostics.PackagesInspected).
			Int("catalog_matches", diagnostics.CatalogMatches).
			Int("unmapped_packages", diagnostics.UnmappedPackages).
			Int("repositories_added", diagnostics.RepositoriesAdded).
			Msg("enriched index report from catalog")
	}
	return scan()
}

func validateCatalogMetadata(metadata catalog.Metadata, report *claircore.IndexReport) error {
	for _, distribution := range report.Distributions {
		if distribution == nil || distribution.DID != "rhel" {
			continue
		}
		version := distribution.VersionID
		if version == "" {
			version = distribution.Version
		}
		if version != metadata.RHELVersion {
			return fmt.Errorf("catalog RHEL version %q does not match discovered version %q", metadata.RHELVersion, version)
		}
		if distribution.Arch != "" && distribution.Arch != metadata.Architecture {
			return fmt.Errorf("catalog architecture %q does not match discovered architecture %q", metadata.Architecture, distribution.Arch)
		}
	}
	return nil
}
