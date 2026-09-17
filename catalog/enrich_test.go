package catalog

import (
	"context"
	"reflect"
	"testing"

	"github.com/quay/claircore"
	"github.com/quay/claircore/pkg/cpe"
)

type enrichReader struct {
	matches map[string][]Match
}

func (r enrichReader) Lookup(_ context.Context, pkg NEVRA) ([]Match, error) {
	return r.matches[pkg.Key()], nil
}

func (enrichReader) Metadata(context.Context) (Metadata, error) { return Metadata{}, nil }
func (enrichReader) RepositoryMappingFile() (string, func(), error) {
	return "", func() {}, nil
}
func (enrichReader) Close() error { return nil }

func TestEnrichIndexReport(t *testing.T) {
	matching := &claircore.Package{ID: "matching", Name: "pkg", Version: "1:2.3-4", Arch: "x86_64"}
	miss := &claircore.Package{ID: "miss", Name: "other", Version: "1.0-1", Arch: "x86_64"}
	existing := &claircore.Package{ID: "existing", Name: "existing", Version: "1.0-1", Arch: "x86_64"}
	matching.RepositoryHint = "unknown-repository"
	report := &claircore.IndexReport{
		Packages: map[string]*claircore.Package{
			matching.ID: matching,
			miss.ID:     miss,
			existing.ID: existing,
		},
		Environments: map[string][]*claircore.Environment{
			matching.ID: {{RepositoryIDs: []string{"unrelated"}}, {}},
			miss.ID:     {{}},
			existing.ID: {{RepositoryIDs: []string{"known"}}},
		},
		Repositories: map[string]*claircore.Repository{
			"unrelated": {ID: "unrelated", URI: "https://unrelated.example"},
			"known":     {ID: "known", URI: "https://known.example"},
		},
	}
	reader := enrichReader{matches: map[string][]Match{
		NEVRA{Name: "pkg", Epoch: "1", Version: "2.3", Release: "4", Arch: "x86_64"}.Key(): {
			{RepositoryID: "baseos", CPE: "cpe:/o:redhat:enterprise_linux:9::baseos"},
			{RepositoryID: "appstream", CPE: "cpe:/o:redhat:enterprise_linux:9::appstream"},
		},
		NEVRA{Name: "existing", Epoch: "0", Version: "1.0", Release: "1", Arch: "x86_64"}.Key(): {
			{RepositoryID: "known", CPE: "cpe:/o:redhat:enterprise_linux:9::baseos"},
		},
	}}

	diagnostics, err := EnrichIndexReport(context.Background(), report, reader)
	if err != nil {
		t.Fatal(err)
	}
	if diagnostics.PackagesInspected != 3 || diagnostics.CatalogMatches != 3 || diagnostics.UnmappedPackages != 1 || diagnostics.RepositoriesAdded != 2 {
		t.Fatalf("unexpected diagnostics: %+v", diagnostics)
	}
	if !reflect.DeepEqual(report.Environments["miss"][0].RepositoryIDs, []string(nil)) {
		t.Fatalf("unmapped package was associated: %#v", report.Environments["miss"][0].RepositoryIDs)
	}
	if !reflect.DeepEqual(report.Environments["existing"][0].RepositoryIDs, []string{"known"}) {
		t.Fatalf("existing association changed: %#v", report.Environments["existing"][0].RepositoryIDs)
	}
	if len(report.Environments["matching"][0].RepositoryIDs) != 3 || len(report.Environments["matching"][1].RepositoryIDs) != 2 {
		t.Fatalf("package environments were not enriched independently: %#v", report.Environments["matching"])
	}
	for _, repositoryID := range report.Environments["matching"][1].RepositoryIDs {
		repository := report.Repositories[repositoryID]
		if repository == nil || repository.Key != "rhel-cpe-repository" || repository.URI == "" {
			t.Fatalf("invalid synthetic repository %q: %#v", repositoryID, repository)
		}
		if _, err := cpe.Unbind(repository.CPE.String()); err != nil {
			t.Fatalf("synthetic repository has invalid CPE: %v", err)
		}
	}

	firstIDs := append([]string(nil), report.Environments["matching"][1].RepositoryIDs...)
	if _, err := EnrichIndexReport(context.Background(), report, reader); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(firstIDs, report.Environments["matching"][1].RepositoryIDs) {
		t.Fatalf("repository IDs are not deterministic: %#v then %#v", firstIDs, report.Environments["matching"][1].RepositoryIDs)
	}
}

func TestEnrichIndexReportRejectsInvalidCPEForExistingRepository(t *testing.T) {
	report := &claircore.IndexReport{
		Packages: map[string]*claircore.Package{
			"pkg": {ID: "pkg", Name: "pkg", Version: "1.0-1", Arch: "x86_64"},
		},
		Environments: map[string][]*claircore.Environment{
			"pkg": {{RepositoryIDs: []string{"repo"}}},
		},
	}
	reader := enrichReader{matches: map[string][]Match{
		NEVRA{Name: "pkg", Epoch: "0", Version: "1.0", Release: "1", Arch: "x86_64"}.Key(): {
			{RepositoryID: "repo", CPE: "not-a-cpe"},
		},
	}}

	if _, err := EnrichIndexReport(context.Background(), report, reader); err == nil {
		t.Fatal("invalid CPE was accepted for an existing repository")
	}
}

func TestEnrichIndexReportDoesNotPartiallyMutateOnInvalidMatch(t *testing.T) {
	report := &claircore.IndexReport{
		Packages: map[string]*claircore.Package{
			"pkg": {ID: "pkg", Name: "pkg", Version: "1.0-1", Arch: "x86_64"},
		},
		Environments: map[string][]*claircore.Environment{"pkg": {{}}},
	}
	reader := enrichReader{matches: map[string][]Match{
		NEVRA{Name: "pkg", Epoch: "0", Version: "1.0", Release: "1", Arch: "x86_64"}.Key(): {
			{RepositoryID: "repo", CPE: "cpe:/o:redhat:enterprise_linux:9::baseos"},
			{RepositoryID: "repo", CPE: "not-a-cpe"},
		},
	}}

	if _, err := EnrichIndexReport(context.Background(), report, reader); err == nil {
		t.Fatal("invalid CPE was accepted")
	}
	if len(report.Repositories) != 0 || len(report.Environments["pkg"][0].RepositoryIDs) != 0 {
		t.Fatalf("report was partially mutated: repositories=%#v environments=%#v", report.Repositories, report.Environments["pkg"])
	}
}
