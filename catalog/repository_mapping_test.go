package catalog

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
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

func TestRepositoryMappingUsesVersionSpecificEntry(t *testing.T) {
	repositoryID := "rhel-9-for-x86_64-baseos-e4s-rpms"
	mapping := RepositoryMapping{data: map[string][]string{
		repositoryID: {
			"cpe:/o:redhat:rhel_e4s:9.4::baseos",
			"cpe:/o:redhat:rhel_eus:9.4::baseos",
		},
		repositoryID + "__9_DOT_4": {"cpe:/o:redhat:rhel_e4s:9.4::baseos"},
	}}

	filtered, err := mapping.forRHELRelease([]string{repositoryID}, "9.4", "x86_64")
	if err != nil {
		t.Fatal(err)
	}
	got, ok := filtered.Lookup(repositoryID)
	want := []string{"cpe:/o:redhat:rhel_e4s:9.4::baseos"}
	if !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("target-specific CPEs = %#v, %v; want %#v", got, ok, want)
	}
}

func TestRepositoryMappingRejectsMissingVersionSpecificEntry(t *testing.T) {
	repositoryID := "rhel-9-for-x86_64-baseos-eus-rpms"
	mapping := RepositoryMapping{data: map[string][]string{
		repositoryID: {
			"cpe:/o:redhat:rhel_eus:9.2::baseos",
			"cpe:/o:redhat:rhel_eus:9.4::baseos",
		},
		repositoryID + "__9_DOT_2": {"cpe:/o:redhat:rhel_eus:9.2::baseos"},
	}}

	if _, err := mapping.forRHELRelease([]string{repositoryID}, "9.4", "x86_64"); err == nil {
		t.Fatal("mapping without an exact 9.4 entry was accepted")
	}
}

func TestRepositoryMappingRejectsE6SWithoutVersionSpecificEntry(t *testing.T) {
	tests := []struct {
		name, repositoryID, targetRelease, cpe, repositoryURL string
	}{
		{
			name:          "RHEL 9 CPE product",
			repositoryID:  "rhel-9-for-x86_64-baseos-e6s-rpms",
			targetRelease: "9.4",
			cpe:           "cpe:/o:redhat:rhel_e6s:9.4::baseos",
			repositoryURL: "content/e6s/rhel9/9.4/x86_64/baseos/os",
		},
		{
			name:          "RHEL 10 CPE product",
			repositoryID:  "rhel-10-for-x86_64-baseos-e6s-rpms",
			targetRelease: "10.2",
			cpe:           "cpe:/o:redhat:enterprise_linux_e6s:10.2",
			repositoryURL: "content/e6s/rhel10/10.2/x86_64/baseos/os",
		},
		{
			name:          "RHEL 10 missing E6S CPE family",
			repositoryID:  "rhel-10-for-x86_64-baseos-e6s-rpms",
			targetRelease: "10.2",
			cpe:           "cpe:/o:redhat:enterprise_linux:10.2",
			repositoryURL: "content/e6s/rhel10/10.2/x86_64/baseos/os",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mappingJSON := `{"data":{"` + test.repositoryID + `":{"cpes":["` + test.cpe + `"],"repo_relative_urls":["` + test.repositoryURL + `"]}}}`
			path := writeMappingFixture(t, []byte(mappingJSON))
			mapping, err := LoadRepositoryMapping(context.Background(), path, "")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := mapping.forRHELRelease([]string{test.repositoryID}, test.targetRelease, "x86_64"); err == nil {
				t.Fatal("E6S mapping without an exact version-specific entry was accepted")
			}
		})
	}
}

func TestRepositoryMappingUsesVersionSpecificEntryWithNewCPEProductName(t *testing.T) {
	repositoryID := "rhel-10-for-x86_64-baseos-eus-rpms"
	mapping := RepositoryMapping{data: map[string][]string{
		repositoryID: {
			"cpe:/o:redhat:enterprise_linux:10.2",
			"cpe:/o:redhat:enterprise_linux_eus:10.0",
			"cpe:/o:redhat:enterprise_linux_eus:10.2",
		},
		repositoryID + "__10_DOT_2": {"cpe:/o:redhat:enterprise_linux_eus:10.2"},
	}}

	filtered, err := mapping.forRHELRelease([]string{repositoryID}, "10.2", "x86_64")
	if err != nil {
		t.Fatal(err)
	}
	got, ok := filtered.Lookup(repositoryID)
	want := []string{"cpe:/o:redhat:enterprise_linux_eus:10.2"}
	if !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("target-specific CPEs = %#v, %v; want %#v", got, ok, want)
	}
}

func TestRepositoryMappingLeavesNonStreamProductVersionUnchanged(t *testing.T) {
	repositoryID := "rhel-9-for-x86_64-sap-netweaver-rpms"
	cpes := []string{"cpe:/a:redhat:sap_hana:9.4::el9"}
	mapping := RepositoryMapping{
		data:             map[string][]string{repositoryID: cpes},
		repoRelativeURLs: map[string][]string{repositoryID: {"content/dist/layered/rhel9/9.4/x86_64/sap-netweaver/os"}},
	}

	filtered, err := mapping.forRHELRelease([]string{repositoryID}, "9.4", "x86_64")
	if err != nil {
		t.Fatal(err)
	}
	got, ok := filtered.Lookup(repositoryID)
	if !ok || !reflect.DeepEqual(got, cpes) {
		t.Fatalf("non-stream CPEs = %#v, %v; want unchanged %#v", got, ok, cpes)
	}
}

func TestRepositoryMappingLeavesBetaRepositoryUnchanged(t *testing.T) {
	repositoryID := "rhel-10-for-aarch64-appstream-beta-rpms"
	path := writeMappingFixture(t, []byte(`{"data":{"rhel-10-for-aarch64-appstream-beta-rpms":{
		"cpes":["cpe:/a:redhat:enterprise_linux:10::appstream"],
		"repo_relative_urls":["content/beta/rhel10/10/aarch64/appstream/os"]
	}}}`))
	mapping, err := LoadRepositoryMapping(context.Background(), path, "")
	if err != nil {
		t.Fatal(err)
	}
	filtered, err := mapping.forRHELRelease([]string{repositoryID}, "10.2", "aarch64")
	if err != nil {
		t.Fatal(err)
	}
	got, ok := filtered.Lookup(repositoryID)
	want := []string{"cpe:/a:redhat:enterprise_linux:10::appstream"}
	if !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("beta repository CPEs = %#v, %v; want unchanged %#v", got, ok, want)
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
