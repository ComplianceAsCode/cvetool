package catalog

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/klauspost/compress/zstd"
)

func TestRepositoryMappingLoadsPlainJSON(t *testing.T) {
	path := writeMappingFixture(t, []byte(`{"data":{"rhel-9-for-x86_64-baseos-rpms":{"cpes":["cpe:/o:redhat:enterprise_linux:9::baseos"]}}}`))
	mapping, err := LoadRepositoryMapping(context.Background(), path, "")
	if err != nil {
		t.Fatal(err)
	}
	got, ok := mapping.Lookup("rhel-9-for-x86_64-baseos-rpms")
	if !ok || len(got) != 1 || got[0] != "cpe:/o:redhat:enterprise_linux:9::baseos" {
		t.Fatalf("unexpected mapping: %#v, %v", got, ok)
	}
}

func TestRepositoryMappingRejectsZstdJSON(t *testing.T) {
	encoder, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatal(err)
	}
	data := encoder.EncodeAll([]byte(`{"data":{"repo":{"cpes":["cpe:/o:redhat:enterprise_linux:9"]}}}`), nil)
	path := filepath.Join(t.TempDir(), "mapping.json.zst")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRepositoryMapping(context.Background(), path, ""); err == nil {
		t.Fatal("compressed mapping unexpectedly loaded")
	}
}

func TestRepositoryMappingRejectsUnknownAndInvalidRepositories(t *testing.T) {
	path := writeMappingFixture(t, []byte(`{"data":{"repo":{"cpes":["not-a-cpe"]}}}`))
	mapping, err := LoadRepositoryMapping(context.Background(), path, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := mapping.Lookup("unknown"); ok {
		t.Fatal("unknown repository unexpectedly found")
	}
	if err := mapping.Validate("unknown"); err == nil {
		t.Fatal("unknown repository was accepted")
	}
	if err := mapping.Validate("repo"); err == nil {
		t.Fatal("invalid CPE was accepted")
	}
}

func TestRepositoryMappingRetainsMultipleCPEs(t *testing.T) {
	path := writeMappingFixture(t, []byte(`{"data":{"repo":{"cpes":["cpe:/o:redhat:enterprise_linux:9","cpe:/a:redhat:enterprise_linux:9"]}}}`))
	mapping, err := LoadRepositoryMapping(context.Background(), path, "")
	if err != nil {
		t.Fatal(err)
	}
	got, ok := mapping.Lookup("repo")
	if !ok || len(got) != 2 {
		t.Fatalf("unexpected CPEs: %#v, %v", got, ok)
	}
}

func writeMappingFixture(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mapping.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	var decoded any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	return path
}
