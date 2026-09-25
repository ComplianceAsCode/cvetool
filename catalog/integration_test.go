package catalog

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ComplianceAsCode/cvetool/datastore/sqlite"
	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln"
	"github.com/quay/claircore/toolkit/types"
)

func TestCatalogRepositoryCPEReachesRHELMatcher(t *testing.T) {
	fixtureDir := filepath.Join("..", "tests", "testdata", "catalog")
	mappingPath := filepath.Join(fixtureDir, "repository-to-cpe.json")
	packages, err := os.ReadFile(filepath.Join(fixtureDir, "packages.tsv"))
	if err != nil {
		t.Fatal(err)
	}

	matcherStore, err := sqlite.NewSQLiteMatcherStore(filepath.Join(t.TempDir(), "matcher.db"), true)
	if err != nil {
		t.Fatal(err)
	}
	vulnerability := &claircore.Vulnerability{
		Name:           "CVE-2026-40355",
		Updater:        "rhel-vex",
		Issued:         time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC),
		Package:        &claircore.Package{Name: "krb5-libs", Version: "1.21.1-10.el9", Arch: "x86_64", Kind: types.BinaryPackage},
		Dist:           &claircore.Distribution{DID: "rhel", VersionID: "9", Arch: "x86_64"},
		Repo:           &claircore.Repository{Key: "rhel-cpe-repository", Name: "cpe:2.3:o:redhat:enterprise_linux:9:*:baseos:*:*:*:*:*"},
		FixedInVersion: "1.21.1-10.el9_8",
		ArchOperation:  claircore.OpEquals,
	}
	if _, err := matcherStore.DeltaUpdateVulnerabilities(context.Background(), "rhel-vex", "fixture", []*claircore.Vulnerability{vulnerability}, nil); err != nil {
		t.Fatal(err)
	}

	lv, err := libvuln.New(context.Background(), &libvuln.Options{
		Client:                   &http.Client{Transport: rejectingTransport{}},
		Store:                    matcherStore,
		Locker:                   fixtureLockSource{},
		DisableBackgroundUpdates: true,
		MatcherNames:             []string{"rhel"},
		UpdaterSets:              []string{},
	})
	if err != nil {
		t.Fatal(err)
	}

	baseReport := fixtureIndexReport()
	withoutCatalog, err := lv.Scan(context.Background(), baseReport)
	if err != nil {
		t.Fatal(err)
	}
	if reportHasVulnerability(withoutCatalog, vulnerability.Name) {
		t.Fatal("candidate vulnerability was reported without catalog enrichment")
	}

	// Generate the catalog from the same offline fixtures used by the regression.
	catalogPath := filepath.Join(t.TempDir(), "catalog.json")
	if err := Generate(context.Background(), GenerateOptions{
		RHELVersion:   "9",
		Architecture:  "x86_64",
		RepositoryIDs: []string{"rhel-9-for-x86_64-baseos-rpms"},
		OutputPath:    catalogPath,
		MappingFile:   mappingPath,
		CommandRunner: fixtureCommandRunner{output: packages},
	}); err != nil {
		t.Fatal(err)
	}
	reader, err := OpenJSONReader(catalogPath)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()

	withCatalogReport := fixtureIndexReport()
	if _, err := EnrichIndexReport(context.Background(), withCatalogReport, reader); err != nil {
		t.Fatal(err)
	}
	withCatalog, err := lv.Scan(context.Background(), withCatalogReport)
	if err != nil {
		t.Fatal(err)
	}
	if !reportHasVulnerability(withCatalog, vulnerability.Name) {
		t.Fatalf("candidate vulnerability was not reported after catalog enrichment: %#v", withCatalog.Vulnerabilities)
	}
}

func reportHasVulnerability(report *claircore.VulnerabilityReport, name string) bool {
	for _, vulnerability := range report.Vulnerabilities {
		if vulnerability.Name == name {
			return true
		}
	}
	return false
}

func fixtureIndexReport() *claircore.IndexReport {
	return &claircore.IndexReport{
		Packages: map[string]*claircore.Package{
			"krb5-libs": {ID: "krb5-libs", Name: "krb5-libs", Version: "0:1.21.1-10.el9", Arch: "x86_64", Kind: types.BinaryPackage, Source: &claircore.Package{}},
		},
		Distributions: map[string]*claircore.Distribution{
			"rhel": {DID: "rhel", VersionID: "9", Arch: "x86_64"},
		},
		Environments: map[string][]*claircore.Environment{
			"krb5-libs": {{DistributionID: "rhel"}},
		},
		Repositories: map[string]*claircore.Repository{},
	}
}

type fixtureCommandRunner struct{ output []byte }

func (r fixtureCommandRunner) Run(context.Context, string, ...string) ([]byte, error) {
	return r.output, nil
}

type fixtureLockSource struct{}

func (fixtureLockSource) TryLock(ctx context.Context, _ string) (context.Context, context.CancelFunc) {
	return ctx, func() {}
}
func (fixtureLockSource) Lock(ctx context.Context, _ string) (context.Context, context.CancelFunc) {
	return ctx, func() {}
}
func (fixtureLockSource) Close(context.Context) error { return nil }

type rejectingTransport struct{}

func (rejectingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("network access disabled in catalog integration test")
}
