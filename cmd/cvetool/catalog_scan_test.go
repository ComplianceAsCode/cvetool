package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ComplianceAsCode/cvetool/catalog"
	"github.com/quay/claircore"
	"github.com/quay/claircore/libindex"
	"github.com/quay/claircore/rhel"
)

func TestExplicitCatalogSkipsAutomaticDNF(t *testing.T) {
	catalogPath := filepath.Join(t.TempDir(), "catalog.json")
	writeScanCatalogFixture(t, catalogPath)
	runner := &scanCatalogRunner{}

	prepared, err := prepareScanCatalogForSource(context.Background(), scanCatalogOptions{
		ExplicitPath: catalogPath,
		TargetRoot:   filepath.Join(t.TempDir(), "missing-target"),
		Runner:       runner,
	}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if prepared == nil || prepared.Reader == nil {
		t.Fatal("explicit catalog was not prepared")
	}
	defer prepared.Close()
	if len(runner.calls) != 0 {
		t.Fatalf("explicit catalog triggered automatic commands: %#v", runner.calls)
	}
}

func TestAutoCatalogSourceRootPath(t *testing.T) {
	root := t.TempDir()
	writeScanCatalogTarget(t, root, "rhel", "9.4")
	mappingPath := writeScanCatalogMapping(t)
	runner := &scanCatalogRunner{}

	prepared, err := prepareScanCatalogForSource(context.Background(), scanCatalogOptions{
		TargetRoot:  root,
		MappingFile: mappingPath,
		Runner:      runner,
	}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if prepared == nil || prepared.Reader == nil {
		t.Fatal("RHEL root-path source did not prepare an automatic catalog")
	}
	defer prepared.Close()
	if !slices.ContainsFunc(runner.calls, func(call []string) bool { return slices.Contains(call, "repoquery") }) {
		t.Fatalf("automatic catalog did not query target packages: %#v", runner.calls)
	}
}

func TestAutoCatalogSourceImagePathWithoutCatalog(t *testing.T) {
	runner := &scanCatalogRunner{}
	prepared, err := prepareScanCatalogForSource(context.Background(), scanCatalogOptions{
		TargetRoot: filepath.Join(t.TempDir(), "missing-target"),
		Runner:     runner,
	}, "image.tar", "")
	if err != nil {
		t.Fatal(err)
	}
	if prepared != nil {
		t.Fatal("image-path source unexpectedly prepared an automatic catalog")
	}
	if len(runner.calls) != 0 {
		t.Fatalf("image-path source triggered target commands: %#v", runner.calls)
	}
}

func TestAutoCatalogRejectsAbsoluteOSReleaseSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	writeScanCatalogTarget(t, root, "rhel", "9.4")
	osReleasePath := filepath.Join(root, "etc", "os-release")
	if err := os.Remove(osReleasePath); err != nil {
		t.Fatal(err)
	}
	hostReleasePath := filepath.Join(t.TempDir(), "os-release")
	if err := os.WriteFile(hostReleasePath, []byte("ID=rhel\nVERSION_ID=9.4\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(hostReleasePath, osReleasePath); err != nil {
		t.Fatal(err)
	}
	runner := &scanCatalogRunner{}
	prepared, err := prepareScanCatalogForSource(context.Background(), scanCatalogOptions{
		TargetRoot:  root,
		MappingFile: writeScanCatalogMapping(t),
		Runner:      runner,
	}, "", "")
	if prepared != nil {
		if closeErr := prepared.Close(); closeErr != nil {
			t.Errorf("close unexpectedly prepared catalog: %v", closeErr)
		}
		t.Fatal("accepted host os-release metadata through an absolute symlink")
	}
	if err == nil {
		t.Fatal("absolute os-release symlink outside target root was not rejected")
	}
	if len(runner.calls) != 0 {
		t.Fatalf("commands ran after absolute os-release symlink escape: %#v", runner.calls)
	}
}

func TestAutoCatalogSupportsRelativeOSReleaseSymlink(t *testing.T) {
	root := t.TempDir()
	writeScanCatalogTarget(t, root, "fedora", "40")
	if err := os.Remove(filepath.Join(root, "etc", "os-release")); err != nil {
		t.Fatal(err)
	}
	targetReleasePath := filepath.Join(root, "usr", "lib", "os-release")
	if err := os.MkdirAll(filepath.Dir(targetReleasePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(targetReleasePath, []byte("ID=rhel\nVERSION_ID=9.4\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..", "usr", "lib", "os-release"), filepath.Join(root, "etc", "os-release")); err != nil {
		t.Fatal(err)
	}
	runner := &scanCatalogRunner{}
	prepared, err := prepareScanCatalogForSource(context.Background(), scanCatalogOptions{
		TargetRoot:  root,
		MappingFile: writeScanCatalogMapping(t),
		Runner:      runner,
	}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if prepared == nil {
		t.Fatal("relative in-root os-release symlink was not accepted")
	}
	defer prepared.Close()
	metadata, err := prepared.Reader.Metadata(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if metadata.RHELVersion != "9" || metadata.Architecture != "x86_64" {
		t.Fatalf("catalog metadata = %#v, want target RHEL 9 x86_64", metadata)
	}
}

func TestAutoCatalogRejectsRepoFileSymlinkEscapeBeforeDNF(t *testing.T) {
	root := t.TempDir()
	writeScanCatalogTarget(t, root, "rhel", "9.4")
	outsideRepo := filepath.Join(t.TempDir(), "host.repo")
	if err := os.WriteFile(outsideRepo, []byte("[host-repo]\nname=host repository\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	repoFile := filepath.Join(root, "etc", "cvetool", "repos.d", "host.repo")
	if err := os.Symlink(outsideRepo, repoFile); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	runner := &scanCatalogRunner{}

	prepared, err := prepareScanCatalogForSource(context.Background(), scanCatalogOptions{
		TargetRoot:  root,
		MappingFile: writeScanCatalogMapping(t),
		Runner:      runner,
	}, "", "")
	if prepared != nil {
		if closeErr := prepared.Close(); closeErr != nil {
			t.Errorf("close unexpectedly prepared catalog: %v", closeErr)
		}
		t.Fatalf("accepted a repository file symlink outside the target root; commands: %#v", runner.calls)
	}
	if err == nil {
		t.Fatalf("repository file symlink outside the target root was not rejected; commands: %#v", runner.calls)
	}
	for _, command := range []string{"repolist", "repoquery"} {
		if hasScanCatalogCommand(runner, command) {
			t.Fatalf("DNF %s ran before rejecting the repository file symlink: %#v", command, runner.calls)
		}
	}
}

func TestAutoCatalogUsesTargetMetadataAndCleansTemporaryFiles(t *testing.T) {
	root := t.TempDir()
	writeScanCatalogTarget(t, root, "rhel", "9.4")
	releasePath := filepath.Join(root, "etc", "dnf", "vars", "releasever")
	if err := os.WriteFile(releasePath, []byte("9.7\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &scanCatalogRunner{}
	options := scanCatalogOptions{TargetRoot: root, MappingFile: writeScanCatalogMapping(t), Runner: runner}

	prepared, err := prepareScanCatalogForSource(context.Background(), options, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if prepared == nil {
		t.Fatal("RHEL target did not produce a scan catalog")
	}
	workDir := prepared.tempDir
	mappingPath := prepared.mappingPath
	if info, err := os.Stat(workDir); err != nil {
		t.Fatalf("private scan directory is missing: %v", err)
	} else if info.Mode().Perm() != 0o700 {
		t.Fatalf("private scan directory mode = %04o, want 0700", info.Mode().Perm())
	}
	if _, err := os.Stat(filepath.Join(workDir, "catalog.json")); err != nil {
		t.Fatalf("generated catalog is missing: %v", err)
	}
	if _, err := os.Stat(mappingPath); err != nil {
		t.Fatalf("temporary repository mapping is missing: %v", err)
	}

	metadata, err := prepared.Reader.Metadata(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if metadata.RHELVersion != "9" || metadata.Architecture != "x86_64" {
		t.Fatalf("catalog metadata = %#v, want target RHEL 9 x86_64", metadata)
	}
	for _, call := range runner.calls {
		if call[0] != "dnf" {
			continue
		}
		joined := strings.Join(call, " ")
		for _, want := range []string{
			"--installroot=" + root,
			"--setopt=reposdir=" + filepath.Join(root, "etc", "cvetool", "repos.d"),
			"--releasever=9.7",
			"--forcearch=x86_64",
		} {
			if !strings.Contains(joined, want) {
				t.Errorf("target DNF command %q missing %q", joined, want)
			}
		}
		switch {
		case slices.Contains(call, "repoquery"):
			if !slices.Contains(call, "--arch=i686,noarch,x86_64") {
				t.Errorf("target repoquery command %q missing target architecture filter", joined)
			}
		case slices.Contains(call, "repolist"):
			for _, arg := range call {
				if strings.HasPrefix(arg, "--arch=") {
					t.Errorf("target repolist command %q contains repoquery-only option %q", joined, arg)
				}
			}
		}
	}

	if err := prepared.Close(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{workDir, mappingPath} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("temporary path %q remains after close: %v", path, err)
		}
	}
}

func TestAutoCatalogFailsWithoutMappedRepositoriesAndCleansScratch(t *testing.T) {
	runner := &scanCatalogRunner{enabledOutput: []byte("repo id repo name\nunmapped-repo Unknown\nrepolist: 1\n")}
	options := scanCatalogTestOptions(t, runner)

	prepared, err := prepareScanCatalogForSource(context.Background(), options, "", "")
	if err == nil || !strings.Contains(err.Error(), "no enabled repositories") {
		t.Fatalf("no mapped repositories error = %v", err)
	}
	if prepared != nil {
		t.Fatal("catalog was returned with no mapped target repositories")
	}
	if hasScanCatalogCommand(runner, "repoquery") {
		t.Fatalf("DNF queried packages despite no mapped repositories: %#v", runner.calls)
	}
	assertScanCatalogScratchRemoved(t, runner)
}

func TestAutoCatalogFailsOnDNFQueryErrorAndCleansScratch(t *testing.T) {
	want := errors.New("target package query failed")
	runner := &scanCatalogRunner{queryErr: want}
	options := scanCatalogTestOptions(t, runner)

	prepared, err := prepareScanCatalogForSource(context.Background(), options, "", "")
	if !errors.Is(err, want) {
		t.Fatalf("DNF query error = %v, want wrapped %v", err, want)
	}
	if prepared != nil {
		t.Fatal("catalog was returned after a DNF query failure")
	}
	assertScanCatalogScratchRemoved(t, runner)
}

func TestAutoCatalogFailsOnMappingErrorAndCleansScratch(t *testing.T) {
	runner := &scanCatalogRunner{}
	options := scanCatalogTestOptions(t, runner)
	options.MappingFile = filepath.Join(t.TempDir(), "missing-mapping.json")

	prepared, err := prepareScanCatalogForSource(context.Background(), options, "", "")
	if err == nil || !strings.Contains(err.Error(), "repository mapping") {
		t.Fatalf("mapping error = %v, want repository mapping failure", err)
	}
	if prepared != nil {
		t.Fatal("catalog was returned after a mapping failure")
	}
	if hasScanCatalogCommand(runner, "repoquery") {
		t.Fatalf("DNF queried packages after mapping load failed: %#v", runner.calls)
	}
	assertScanCatalogScratchRemoved(t, runner)
}

func TestAutoCatalogFailsOnAmbiguousTargetMetadata(t *testing.T) {
	runner := &scanCatalogRunner{rpmOutput: []byte("x86_64\naarch64\n")}
	options := scanCatalogTestOptions(t, runner)

	prepared, err := prepareScanCatalogForSource(context.Background(), options, "", "")
	if err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("ambiguous target architecture error = %v", err)
	}
	if prepared != nil {
		t.Fatal("catalog was returned for ambiguous target metadata")
	}
	if len(runner.calls) != 1 || runner.calls[0][0] != "rpm" {
		t.Fatalf("DNF ran before target metadata was resolved: %#v", runner.calls)
	}
}

func TestAutoCatalogSkipsUnknownRepositoriesWhenMappedRepositoriesRemain(t *testing.T) {
	runner := &scanCatalogRunner{enabledOutput: []byte(
		"repo id repo name\nunmapped-repo Unknown\nrhel-9-for-x86_64-baseos-rpms BaseOS\nrepolist: 2\n",
	)}
	options := scanCatalogTestOptions(t, runner)
	prepared, err := prepareScanCatalogForSource(context.Background(), options, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if prepared == nil {
		t.Fatal("catalog was not generated from the mapped repository")
	}
	defer prepared.Close()

	var queried []string
	for _, call := range runner.calls {
		if !slices.Contains(call, "repoquery") {
			continue
		}
		for _, arg := range call {
			if strings.HasPrefix(arg, "--repo=") {
				queried = append(queried, strings.TrimPrefix(arg, "--repo="))
			}
		}
	}
	if !slices.Equal(queried, []string{"rhel-9-for-x86_64-baseos-rpms"}) {
		t.Fatalf("queried repository IDs = %v, want only the mapped ID", queried)
	}
}

func TestAutoCatalogDoesNotEnterRHELPathForNonRHELRoot(t *testing.T) {
	root := t.TempDir()
	writeScanCatalogTarget(t, root, "fedora", "40")
	runner := &scanCatalogRunner{}
	prepared, err := prepareScanCatalogForSource(context.Background(), scanCatalogOptions{
		TargetRoot: root,
		Runner:     runner,
	}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if prepared != nil || len(runner.calls) != 0 {
		t.Fatalf("non-RHEL root entered automatic catalog path: prepared=%v calls=%#v", prepared != nil, runner.calls)
	}
}

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

	prepared, err := prepareScanCatalog(context.Background(), scanCatalogOptions{ExplicitPath: catalogPath})
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	var opts libindex.Options
	if err := prepared.configureScanner(&opts); err != nil {
		t.Fatal(err)
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
	if err := prepared.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(config.Repo2CPEMappingFile); !os.IsNotExist(err) {
		t.Fatalf("mapping file still exists after cleanup: %v", err)
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

	prepared, err := prepareScanCatalog(context.Background(), scanCatalogOptions{ExplicitPath: catalogPath})
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	var opts libindex.Options
	if err := prepared.configureScanner(&opts); err != nil {
		t.Fatal(err)
	}

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
	closeErr     error
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
func (r *scanCatalogReader) Close() error                                 { return r.closeErr }

func TestCatalogCloseErrorIsReturned(t *testing.T) {
	want := errors.New("close failed")
	prepared := &scanCatalog{Reader: &scanCatalogReader{closeErr: want}}
	if err := prepared.Close(); !errors.Is(err, want) {
		t.Fatalf("closeCatalog error = %v, want %v", err, want)
	}
}

func TestCatalogCloseErrorJoinsScanError(t *testing.T) {
	scanErr := errors.New("scan failed")
	closeErr := errors.New("close failed")
	prepared := &scanCatalog{Reader: &scanCatalogReader{closeErr: closeErr}}

	err := closeScanCatalog(scanErr, prepared)
	if !errors.Is(err, scanErr) || !errors.Is(err, closeErr) {
		t.Fatalf("joined scan/catalog error = %v, want both %v and %v", err, scanErr, closeErr)
	}
}

func TestCatalogCloseRemovesMappingFile(t *testing.T) {
	mappingPath := filepath.Join(t.TempDir(), "mapping.json")
	if err := os.WriteFile(mappingPath, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	prepared := &scanCatalog{mappingPath: mappingPath, mappingCleanup: func() {}}

	if err := prepared.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(mappingPath); !os.IsNotExist(err) {
		t.Fatalf("temporary mapping file remains after close: %v", err)
	}
}

func TestCatalogCloseJoinsMappingRemovalError(t *testing.T) {
	mappingPath := filepath.Join(t.TempDir(), "mapping.json")
	if err := os.Mkdir(mappingPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mappingPath, "child"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	scanErr := errors.New("scan failed")
	prepared := &scanCatalog{mappingPath: mappingPath, mappingCleanup: func() {}}

	err := closeScanCatalog(scanErr, prepared)
	if !errors.Is(err, scanErr) {
		t.Fatalf("joined error = %v, want scan error %v", err, scanErr)
	}
	var pathErr *os.PathError
	if !errors.As(err, &pathErr) {
		t.Fatalf("joined error = %v, want mapping removal error", err)
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

type scanCatalogRunner struct {
	calls         [][]string
	rpmOutput     []byte
	enabledOutput []byte
	queryOutput   []byte
	queryErr      error
}

func (r *scanCatalogRunner) Run(_ context.Context, path string, args ...string) ([]byte, error) {
	call := append([]string{path}, args...)
	r.calls = append(r.calls, call)
	switch {
	case path == "rpm":
		if r.rpmOutput != nil {
			return r.rpmOutput, nil
		}
		return []byte("x86_64\ni686\nnoarch\n"), nil
	case slices.Contains(args, "repolist"):
		if r.enabledOutput != nil {
			return r.enabledOutput, nil
		}
		return []byte("repo id repo name\nrhel-9-for-x86_64-baseos-rpms BaseOS\nrepolist: 1\n"), nil
	case slices.Contains(args, "repoquery"):
		if r.queryErr != nil {
			return nil, r.queryErr
		}
		if r.queryOutput != nil {
			return r.queryOutput, nil
		}
		return []byte("bash\t0\t5.1.8\t6.el9\tx86_64\n"), nil
	default:
		return nil, errors.New("unexpected command")
	}
}

func scanCatalogTestOptions(t *testing.T, runner *scanCatalogRunner) scanCatalogOptions {
	t.Helper()
	root := t.TempDir()
	writeScanCatalogTarget(t, root, "rhel", "9.4")
	return scanCatalogOptions{TargetRoot: root, MappingFile: writeScanCatalogMapping(t), Runner: runner}
}

func hasScanCatalogCommand(runner *scanCatalogRunner, command string) bool {
	for _, call := range runner.calls {
		if slices.Contains(call, command) {
			return true
		}
	}
	return false
}

func assertScanCatalogScratchRemoved(t *testing.T, runner *scanCatalogRunner) {
	t.Helper()
	for _, call := range runner.calls {
		for _, arg := range call {
			if !strings.HasPrefix(arg, "--setopt=cachedir=") {
				continue
			}
			cacheDir := strings.TrimPrefix(arg, "--setopt=cachedir=")
			workDir := filepath.Dir(cacheDir)
			if _, err := os.Stat(workDir); !os.IsNotExist(err) {
				t.Fatalf("scan scratch directory %q remains after preparation failure: %v", workDir, err)
			}
			return
		}
	}
	t.Fatal("no target DNF command recorded a scratch path")
}

func writeScanCatalogFixture(t *testing.T, path string) {
	t.Helper()
	writer, err := catalog.NewJSONWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.AddRepository(catalog.Repository{
		ID:   "rhel-9-for-x86_64-baseos-rpms",
		CPEs: []string{"cpe:/o:redhat:enterprise_linux:9::baseos"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := writer.SetMetadata(catalog.Metadata{RHELVersion: "9", Architecture: "x86_64", GeneratedAt: now()}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
}

func writeScanCatalogMapping(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mapping.json")
	if err := os.WriteFile(path, []byte(`{"data":{"rhel-9-for-x86_64-baseos-rpms":{"cpes":["cpe:/o:redhat:enterprise_linux:9::baseos"]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeScanCatalogTarget(t *testing.T, root, id, version string) {
	t.Helper()
	files := map[string]string{
		"etc/os-release":          "ID=" + id + "\nVERSION_ID=" + version + "\n",
		"etc/dnf/dnf.conf":        "[main]\nreposdir=/etc/cvetool/repos.d\n",
		"etc/dnf/vars/releasever": version + "\n",
	}
	for path, contents := range files {
		fullPath := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fullPath, []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, "etc", "cvetool", "repos.d"), 0o755); err != nil {
		t.Fatal(err)
	}
}
