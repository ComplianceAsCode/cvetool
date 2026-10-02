package catalog

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestJSONCatalogRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "catalog.json")
	writer, err := NewJSONWriter(path)
	if err != nil {
		t.Fatal(err)
	}

	metadata := Metadata{
		SchemaVersion:      "1",
		RHELVersion:        "9",
		Architecture:       "x86_64",
		RepositoryIDs:      []string{"rhel-9-for-x86_64-baseos-rpms"},
		MappingSource:      "fixture",
		MappingFingerprint: "mapping-sha",
		PackageFingerprint: "packages-sha",
		GeneratedAt:        time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC),
	}
	if err := writer.SetMetadata(metadata); err != nil {
		t.Fatal(err)
	}
	if err := writer.AddRepository(Repository{ID: "baseos", CPEs: []string{"cpe:/o:redhat:enterprise_linux:9"}}); err != nil {
		t.Fatal(err)
	}
	if err := writer.AddRepository(Repository{ID: "appstream", CPEs: []string{"cpe:/o:redhat:enterprise_linux:9", "cpe:/a:redhat:enterprise_linux:9"}}); err != nil {
		t.Fatal(err)
	}
	pkg := NEVRA{Name: "bash", Epoch: "0", Version: "5.1.8", Release: "6.el9", Arch: "x86_64"}
	if err := writer.AddPackage(pkg, Match{RepositoryID: "baseos", CPE: "cpe:/o:redhat:enterprise_linux:9"}); err != nil {
		t.Fatal(err)
	}
	for _, match := range []Match{
		{RepositoryID: "appstream", CPE: "cpe:/a:redhat:enterprise_linux:9"},
		{RepositoryID: "appstream", CPE: "cpe:/o:redhat:enterprise_linux:9"},
	} {
		if err := writer.AddPackage(pkg, match); err != nil {
			t.Fatal(err)
		}
		if err := writer.AddPackage(pkg, match); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	reader, err := OpenJSONReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()

	gotMetadata, err := reader.Metadata(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(metadata, gotMetadata) {
		t.Fatalf("metadata mismatch: %#v != %#v", gotMetadata, metadata)
	}
	got, err := reader.Lookup(context.Background(), pkg)
	if err != nil {
		t.Fatal(err)
	}
	want := []Match{
		{RepositoryID: "appstream", CPE: "cpe:/a:redhat:enterprise_linux:9"},
		{RepositoryID: "appstream", CPE: "cpe:/o:redhat:enterprise_linux:9"},
		{RepositoryID: "baseos", CPE: "cpe:/o:redhat:enterprise_linux:9"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("matches mismatch: %#v != %#v", got, want)
	}
	unknown, err := reader.Lookup(context.Background(), NEVRA{Name: "unknown", Epoch: "0", Version: "1", Release: "1", Arch: "noarch"})
	if err != nil {
		t.Fatal(err)
	}
	if len(unknown) != 0 {
		t.Fatalf("unknown package returned matches: %#v", unknown)
	}
}

func TestJSONReaderRejectsInvalidInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "catalog.json")
	if err := os.WriteFile(path, []byte("not-json"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenJSONReader(path); err == nil {
		t.Fatal("reader accepted invalid JSON")
	}
}
