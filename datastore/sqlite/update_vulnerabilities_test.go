package sqlite

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/quay/claircore"
)

func latestFixedInByName(t *testing.T, store *sqliteMatcherStore, updater string) map[string][]string {
	t.Helper()
	rows, err := store.conn.Query(`
		SELECT name.value, vuln.fixed_in_version
		FROM vuln
		INNER JOIN metadata AS name ON vuln.name_id = name.id
		INNER JOIN uo_vuln ON vuln.id = uo_vuln.vuln
		INNER JOIN latest_update_operations ON latest_update_operations.id = uo_vuln.uo
		WHERE latest_update_operations.kind = 'vulnerability'
		  AND vuln.updater = ?
		ORDER BY name.value, vuln.fixed_in_version
	`, updater)
	if err != nil {
		t.Fatalf("query latest vulns: %v", err)
	}
	defer rows.Close()

	out := map[string][]string{}
	for rows.Next() {
		var name, fixed string
		if err := rows.Scan(&name, &fixed); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out[name] = append(out[name], fixed)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	return out
}

// Regression: after migration 02, vuln names live in metadata via name_id.
// Selecting "name" from vuln on SQLite silently becomes the string literal
// "name", so delta carry-forward never drops updated/deleted advisories and
// stale FixedInVersion rows stay queryable after cvetool update.
func TestDeltaUpdateDropsReplacedAndDeletedByName(t *testing.T) {
	ctx := context.Background()
	store, err := NewSQLiteMatcherStore(filepath.Join(t.TempDir(), "matcher.db"), true)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}

	updater := "test-updater"
	pkg := &claircore.Package{Name: "pkg", Kind: "binary"}
	dist := &claircore.Distribution{DID: "rhel", Name: "RHEL", Version: "9"}

	old := &claircore.Vulnerability{
		Name:           "CVE-2024-0001",
		Updater:        updater,
		Description:    "old",
		Package:        pkg,
		Dist:           dist,
		FixedInVersion: "1.0.0",
	}
	if _, err := store.DeltaUpdateVulnerabilities(ctx, updater, "fp1", []*claircore.Vulnerability{old}, nil); err != nil {
		t.Fatalf("initial delta: %v", err)
	}

	// Seed an advisory that should carry forward and one that will be deleted.
	staleAlso := &claircore.Vulnerability{
		Name:           "CVE-2024-0002",
		Updater:        updater,
		Description:    "carry",
		Package:        pkg,
		Dist:           dist,
		FixedInVersion: "1.0.0",
	}
	toDelete := &claircore.Vulnerability{
		Name:           "CVE-2024-0003",
		Updater:        updater,
		Description:    "delete-me",
		Package:        pkg,
		Dist:           dist,
		FixedInVersion: "1.0.0",
	}
	if _, err := store.DeltaUpdateVulnerabilities(ctx, updater, "fp2", []*claircore.Vulnerability{staleAlso, toDelete}, nil); err != nil {
		t.Fatalf("seed carry/delete candidates: %v", err)
	}

	updated := &claircore.Vulnerability{
		Name:           "CVE-2024-0001",
		Updater:        updater,
		Description:    "new",
		Package:        pkg,
		Dist:           dist,
		FixedInVersion: "2.0.0",
	}
	if _, err := store.DeltaUpdateVulnerabilities(ctx, updater, "fp3", []*claircore.Vulnerability{updated}, []string{"CVE-2024-0003"}); err != nil {
		t.Fatalf("delta with replace+delete: %v", err)
	}

	byName := latestFixedInByName(t, store, updater)

	if got := byName["CVE-2024-0001"]; len(got) != 1 || got[0] != "2.0.0" {
		t.Errorf("CVE-2024-0001 FixedInVersion = %v, want [2.0.0] only (stale 1.0.0 must not carry forward)", got)
	}
	if got := byName["CVE-2024-0002"]; len(got) != 1 || got[0] != "1.0.0" {
		t.Errorf("CVE-2024-0002 FixedInVersion = %v, want carried-forward [1.0.0]", got)
	}
	if _, ok := byName["CVE-2024-0003"]; ok {
		t.Errorf("CVE-2024-0003 still present after delete: %v", byName["CVE-2024-0003"])
	}
}
