package catalog

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestGenerateRequiresInputs(t *testing.T) {
	base := GenerateOptions{Architecture: "x86_64", RepositoryIDs: []string{"repo"}, OutputPath: "out"}
	for name, options := range map[string]GenerateOptions{
		"version": base,
		"arch":    {RHELVersion: "9", RepositoryIDs: []string{"repo"}, OutputPath: "out"},
		"repos":   {RHELVersion: "9", Architecture: "x86_64", OutputPath: "out"},
		"output":  {RHELVersion: "9", Architecture: "x86_64", RepositoryIDs: []string{"repo"}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := Generate(context.Background(), options); err == nil {
				t.Fatal("Generate succeeded")
			}
		})
	}
}

func TestGenerateIndexesRepositoriesAndMetadata(t *testing.T) {
	dir := t.TempDir()
	mappingPath := filepath.Join(dir, "mapping.json")
	if err := os.WriteFile(mappingPath, []byte(`{"data":{"arepo":{"cpes":["cpe:/o:redhat:enterprise_linux:9","cpe:/a:redhat:enterprise_linux:9"]},"zrepo":{"cpes":["cpe:/o:redhat:enterprise_linux:9"]}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	runner := &fakeCommandRunner{output: []byte("bash\t0\t5.1.8\t6.el9\tx86_64\n")}
	output := filepath.Join(dir, "catalog.json")
	err := Generate(context.Background(), GenerateOptions{
		RHELVersion: "9", Architecture: "x86_64", RepositoryIDs: []string{"zrepo", "arepo"},
		OutputPath: output, MappingFile: mappingPath, DNFPath: "dnf", CommandRunner: runner,
	})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := OpenJSONReader(output)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	matches, err := reader.Lookup(context.Background(), NEVRA{Name: "bash", Epoch: "0", Version: "5.1.8", Release: "6.el9", Arch: "x86_64"})
	if err != nil || len(matches) != 3 {
		t.Fatalf("unexpected matches: %#v, %v", matches, err)
	}
	metadata, err := reader.Metadata(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if metadata.RHELVersion != "9" || metadata.Architecture != "x86_64" || !reflect.DeepEqual(metadata.RepositoryIDs, []string{"arepo", "zrepo"}) || metadata.MappingFingerprint == "" || metadata.PackageFingerprint == "" {
		t.Fatalf("incomplete metadata: %#v", metadata)
	}
	if _, err := os.Stat(output + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temporary output remains: %v", err)
	}
}

func TestGenerateRejectsUnmappedRepository(t *testing.T) {
	dir := t.TempDir()
	mappingPath := filepath.Join(dir, "mapping.json")
	if err := os.WriteFile(mappingPath, []byte(`{"data":{"other":{"cpes":["cpe:/o:redhat:enterprise_linux:9"]}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	err := Generate(context.Background(), GenerateOptions{RHELVersion: "9", Architecture: "x86_64", RepositoryIDs: []string{"repo"}, OutputPath: filepath.Join(dir, "catalog.json"), MappingFile: mappingPath, CommandRunner: &fakeCommandRunner{}})
	if err == nil {
		t.Fatal("Generate accepted an unmapped repository")
	}
}
