package sqlite

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/quay/claircore"
	"github.com/quay/claircore/datastore"
	"github.com/quay/claircore/toolkit/types"
)

func TestCIMatcherFixtureContainsSampleVulnerability(t *testing.T) {
	dbPath := filepath.Join("..", "..", "tests", "testdata", "matcher.db")
	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open CI matcher fixture: %v", err)
	}
	defer conn.Close()
	store := &sqliteMatcherStore{conn: conn}

	record := &claircore.IndexRecord{
		Package: &claircore.Package{
			ID:     "fixture-package",
			Name:   "glibc",
			Kind:   types.BinaryPackage,
			Source: &claircore.Package{},
		},
		Distribution: &claircore.Distribution{},
		Repository:   &claircore.Repository{},
	}
	got, err := store.Get(context.Background(), []*claircore.IndexRecord{record}, datastore.GetOpts{})
	if err != nil {
		t.Fatalf("query CI matcher fixture: %v", err)
	}

	vulns := got[record.Package.ID]
	if len(vulns) != 1 {
		t.Fatalf("fixture returned %d vulnerabilities for glibc, want 1", len(vulns))
	}
	if vulns[0].Name != "CVE-2099-0001" {
		t.Errorf("fixture CVE = %q, want CVE-2099-0001", vulns[0].Name)
	}
}
