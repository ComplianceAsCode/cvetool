package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"time"

	ds_sqlite "github.com/ComplianceAsCode/cvetool/datastore/sqlite"
	"github.com/quay/claircore"
	"github.com/quay/claircore/toolkit/types"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: go run tests/fixture_gen.go <new-db-path>")
	}
	if err := generateFixture(os.Args[1]); err != nil {
		log.Fatal(err)
	}
}

func generateFixture(path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("refusing to overwrite existing database %q", path)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	store, err := ds_sqlite.NewSQLiteMatcherStore(path, true)
	if err != nil {
		return fmt.Errorf("create matcher database: %w", err)
	}

	vuln := &claircore.Vulnerability{
		Name:               "CVE-2099-0001",
		Description:        "Test-only CI fixture vulnerability for matching glibc on RHEL 10; this does not represent a real advisory.",
		Issued:             time.Time{},
		Severity:           "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		NormalizedSeverity: claircore.High,
		Updater:            "rhel-vex",
		Package: &claircore.Package{
			Name: "glibc",
			Kind: types.BinaryPackage,
		},
		Dist: &claircore.Distribution{},
		Repo: &claircore.Repository{
			Name: "cpe:2.3:o:redhat:enterprise_linux:10:*:*:*:*:*:*:*",
			Key:  "rhel-cpe-repository",
		},
	}
	if _, err := store.UpdateVulnerabilities(context.Background(), "rhel-vex", "ci-fixture-v1", []*claircore.Vulnerability{vuln}); err != nil {
		return fmt.Errorf("insert matcher fixture data: %w", err)
	}
	return nil
}
