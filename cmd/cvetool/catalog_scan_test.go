package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ComplianceAsCode/cvetool/catalog"
	"github.com/quay/claircore"
	"github.com/quay/claircore/libindex"
	"github.com/quay/claircore/rhel"
)

func TestCatalogScanConfiguration(t *testing.T) {
	dir := t.TempDir()
	catalogPath := filepath.Join(dir, "catalog.json")
	writer, err := catalog.NewJSONWriter(catalogPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.AddRepository(catalog.Repository{
		ID:   "rhel-9-for-x86_64-baseos-rpms",
		CPEs: []string{"cpe:/o:redhat:enterprise_linux:9::baseos"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := writer.SetMetadata(catalog.Metadata{RHELVersion: "9", Architecture: "x86_64", RepositoryIDs: []string{"rhel-9-for-x86_64-baseos-rpms"}, GeneratedAt: now()}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	var opts libindex.Options
	reader, cleanup, err := configureCatalogScanner(catalogPath, &opts)
	if err != nil {
		t.Fatal(err)
	}
	if reader == nil || cleanup == nil {
		t.Fatal("catalog configuration did not return reader and cleanup")
	}
	var config rhel.RepositoryScannerConfig
	if err := opts.ScannerConfig.Repo["rhel-repository-scanner"](&config); err != nil {
		t.Fatal(err)
	}
	if config.Repo2CPEMappingFile == "" {
		t.Fatal("catalog configuration did not set a mapping file")
	}
	if config.Repo2CPEMappingURL != "" {
		t.Fatalf("catalog configuration set an HTTP mapping URL: %q", config.Repo2CPEMappingURL)
	}
	if _, err := os.Stat(config.Repo2CPEMappingFile); err != nil {
		t.Fatalf("mapping file is not readable: %v", err)
	}
	cleanup()
	if _, err := os.Stat(config.Repo2CPEMappingFile); !os.IsNotExist(err) {
		t.Fatalf("mapping file still exists after cleanup: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCatalogScanConfigurationWithoutCatalog(t *testing.T) {
	var opts libindex.Options
	reader, cleanup, err := configureCatalogScanner("", &opts)
	if err != nil {
		t.Fatal(err)
	}
	if reader != nil || cleanup != nil || opts.ScannerConfig.Repo != nil {
		t.Fatal("scan without a catalog changed repository scanner defaults")
	}
}

func TestCatalogScanValidatesReleaseAndArchitecture(t *testing.T) {
	metadata := catalog.Metadata{RHELVersion: "9", Architecture: "x86_64"}
	matching := &claircore.IndexReport{Distributions: map[string]*claircore.Distribution{
		"rhel": {DID: "rhel", VersionID: "9", Arch: "x86_64"},
	}}
	if err := validateCatalogMetadata(metadata, matching); err != nil {
		t.Fatal(err)
	}

	for name, dist := range map[string]*claircore.Distribution{
		"release":      {DID: "rhel", VersionID: "8", Arch: "x86_64"},
		"architecture": {DID: "rhel", VersionID: "9", Arch: "aarch64"},
	} {
		t.Run(name, func(t *testing.T) {
			err := validateCatalogMetadata(metadata, &claircore.IndexReport{Distributions: map[string]*claircore.Distribution{"rhel": dist}})
			if err == nil || !strings.Contains(err.Error(), "catalog") {
				t.Fatalf("expected catalog mismatch error, got %v", err)
			}
		})
	}
}

func TestCatalogRHELRepositoryScannerDoesNotFetchMapping(t *testing.T) {
	dir := t.TempDir()
	catalogPath := filepath.Join(dir, "catalog.json")
	writer, err := catalog.NewJSONWriter(catalogPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.AddRepository(catalog.Repository{
		ID:   "rhel-9-for-x86_64-baseos-rpms",
		CPEs: []string{"cpe:/o:redhat:enterprise_linux:9::baseos"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	var opts libindex.Options
	reader, cleanup, err := configureCatalogScanner(catalogPath, &opts)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	defer reader.Close()

	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("catalog-backed repository scanner made an HTTP mapping request")
	}))
	defer server.Close()
	requests := 0
	serverClient := server.Client()
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		request.URL.Scheme = "http"
		request.URL.Host = strings.TrimPrefix(server.URL, "http://")
		return serverClient.Transport.RoundTrip(request)
	})}
	scanner := &rhel.RepositoryScanner{}
	if err := scanner.Configure(context.Background(), opts.ScannerConfig.Repo["rhel-repository-scanner"], client); err != nil {
		t.Fatal(err)
	}

	root := filepath.Join(dir, "root")
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "os-release"), []byte("NAME=\"Red Hat Enterprise Linux\"\nVERSION_ID=\"9\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var layer claircore.Layer
	if err := layer.Init(context.Background(), &claircore.LayerDescription{
		Digest:    "sha256:" + strings.Repeat("a", 64),
		URI:       "file://" + root,
		MediaType: "application/vnd.claircore.filesystem",
	}, nil); err != nil {
		t.Fatal(err)
	}
	defer layer.Close()
	if _, err := scanner.Scan(context.Background(), &layer); err != nil {
		t.Fatal(err)
	}
	if requests != 0 {
		t.Fatalf("catalog-backed repository scanner made %d HTTP requests", requests)
	}
}

func TestCatalogScanRejectsMismatchBeforeVulnerabilityScan(t *testing.T) {
	dir := t.TempDir()
	catalogPath := filepath.Join(dir, "catalog.json")
	writer, err := catalog.NewJSONWriter(catalogPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.SetMetadata(catalog.Metadata{RHELVersion: "8", Architecture: "aarch64", GeneratedAt: now()}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	reader, err := catalog.OpenJSONReader(catalogPath)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()

	called := false
	err = scanWithCatalogValidation(context.Background(), reader, &claircore.IndexReport{Distributions: map[string]*claircore.Distribution{
		"rhel": {DID: "rhel", VersionID: "9", Arch: "x86_64"},
	}}, func() error {
		called = true
		return nil
	})
	if err == nil {
		t.Fatal("incompatible catalog was accepted")
	}
	if called {
		t.Fatal("vulnerability scan was called after catalog validation failed")
	}
}

func TestCatalogScanEnrichesBeforeVulnerabilityScan(t *testing.T) {
	reader := &scanCatalogReader{
		metadata: catalog.Metadata{RHELVersion: "9", Architecture: "x86_64"},
		matches:  []catalog.Match{{RepositoryID: "baseos", CPE: "cpe:/o:redhat:enterprise_linux:9::baseos"}},
	}
	report := &claircore.IndexReport{
		Packages: map[string]*claircore.Package{
			"pkg": {ID: "pkg", Name: "pkg", Version: "1.0-1", Arch: "x86_64"},
		},
		Distributions: map[string]*claircore.Distribution{
			"rhel": {DID: "rhel", VersionID: "9", Arch: "x86_64"},
		},
		Environments: map[string][]*claircore.Environment{"pkg": {{}}},
		Repositories: map[string]*claircore.Repository{},
	}
	called := false
	err := scanWithCatalogValidation(context.Background(), reader, report, func() error {
		called = true
		if len(report.Environments["pkg"][0].RepositoryIDs) != 1 {
			t.Fatalf("catalog repository was not attached before vulnerability scan: %#v", report.Environments["pkg"][0].RepositoryIDs)
		}
		if len(report.Repositories) != 1 {
			t.Fatalf("catalog repository was not visible before vulnerability scan: %#v", report.Repositories)
		}
		records := report.IndexRecords()
		if len(records) != 1 || records[0].Repository == nil || records[0].Repository.Key != "rhel-cpe-repository" {
			t.Fatalf("catalog repository was not visible to matching: %#v", records)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !called || !reader.metadataRead || !reader.lookupCalled {
		t.Fatalf("catalog scan order was not exercised: called=%v metadata=%v lookup=%v", called, reader.metadataRead, reader.lookupCalled)
	}
}

type scanCatalogReader struct {
	metadata     catalog.Metadata
	metadataRead bool
	lookupCalled bool
	matches      []catalog.Match
}

func (r *scanCatalogReader) Lookup(context.Context, catalog.NEVRA) ([]catalog.Match, error) {
	r.lookupCalled = true
	return r.matches, nil
}
func (r *scanCatalogReader) Metadata(context.Context) (catalog.Metadata, error) {
	r.metadataRead = true
	return r.metadata, nil
}
func (*scanCatalogReader) RepositoryMappingFile() (string, func(), error) { return "", func() {}, nil }
func (*scanCatalogReader) Close() error                                   { return nil }

func TestCatalogCloseErrorIsReturned(t *testing.T) {
	want := errors.New("close failed")
	if err := closeCatalog(func() error { return want }); !errors.Is(err, want) {
		t.Fatalf("closeCatalog error = %v, want %v", err, want)
	}
}

func TestCatalogAdvice(t *testing.T) {
	advice := catalogAdvice(0, "")
	if !strings.Contains(advice, "cvetool catalog") || !strings.Contains(advice, "--catalog <path>") {
		t.Fatalf("catalog advice = %q, want catalog command and scan flag", advice)
	}
}

func TestCatalogAdviceNotNeeded(t *testing.T) {
	for name, args := range map[string]struct {
		vulnerabilities int
		catalogPath     string
	}{
		"vulnerabilities found": {vulnerabilities: 1},
		"catalog provided":      {catalogPath: "catalog.json"},
	} {
		t.Run(name, func(t *testing.T) {
			if advice := catalogAdvice(args.vulnerabilities, args.catalogPath); advice != "" {
				t.Fatalf("catalog advice = %q, want no advice", advice)
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func now() (result time.Time) { return time.Now().UTC() }
