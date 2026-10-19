package catalog

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
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
	scratchDir, err := os.MkdirTemp(dir, "dnf-scratch-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(scratchDir, 0o700); err != nil {
		t.Fatal(err)
	}
	mappingPath := filepath.Join(dir, "mapping.json")
	if err := os.WriteFile(mappingPath, []byte(`{"data":{"arepo":{"cpes":["cpe:/o:redhat:enterprise_linux:10","cpe:/a:redhat:enterprise_linux:10"]},"zrepo":{"cpes":["cpe:/o:redhat:enterprise_linux:10"]}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	runner := &fakeCommandRunner{output: []byte("bash\t0\t5.1.8\t6.el10\tx86_64\n")}
	output := filepath.Join(dir, "catalog.json")
	err = Generate(context.Background(), GenerateOptions{
		RHELVersion: "10", Architecture: "x86_64", RepositoryIDs: []string{"zrepo", "arepo"},
		OutputPath: output, MappingFile: mappingPath, DNFPath: "dnf", CommandRunner: runner,
		DNF: DNFOptions{
			Path: "dnf", InstallRoot: "/target", ScratchDir: scratchDir, ReleaseVersion: "10.2",
			RepoDirs:      []string{"/target/etc/yum.repos.d"},
			Architectures: []string{"i686", "noarch", "x86_64"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.args) != 2 {
		t.Fatalf("DNF query count = %d, want one query per repository: %#v", len(runner.args), runner.args)
	}
	for _, args := range runner.args {
		if !slices.Contains(args, "--installroot=/target") || !slices.Contains(args, "--releasever=10.2") || !slices.Contains(args, "--forcearch=x86_64") || !slices.Contains(args, "--arch=i686,noarch,x86_64") {
			t.Fatalf("query did not use target metadata and all package architectures: %#v", args)
		}
	}
	reader, err := OpenJSONReader(output)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	matches, err := reader.Lookup(context.Background(), NEVRA{Name: "bash", Epoch: "0", Version: "5.1.8", Release: "6.el10", Arch: "x86_64"})
	if err != nil || len(matches) != 3 {
		t.Fatalf("unexpected matches: %#v, %v", matches, err)
	}
	metadata, err := reader.Metadata(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if metadata.RHELVersion != "10" || metadata.Architecture != "x86_64" || !reflect.DeepEqual(metadata.RepositoryIDs, []string{"arepo", "zrepo"}) || metadata.MappingFingerprint == "" || metadata.PackageFingerprint == "" {
		t.Fatalf("incomplete metadata: %#v", metadata)
	}
	if _, err := os.Stat(output + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temporary output remains: %v", err)
	}
}

func TestGenerateSelectsEUSCPEForTargetRelease(t *testing.T) {
	dir := t.TempDir()
	scratchDir, err := os.MkdirTemp(dir, "dnf-scratch-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(scratchDir, 0o700); err != nil {
		t.Fatal(err)
	}
	mappingPath := filepath.Join(dir, "mapping.json")
	if err := os.WriteFile(mappingPath, []byte(`{"data":{"eus-baseos":{"cpes":[
		"cpe:/o:redhat:enterprise_linux:9::baseos",
		"cpe:/o:redhat:rhel_eus:9.0::baseos",
		"cpe:/o:redhat:rhel_eus:9.2::baseos",
		"cpe:/o:redhat:rhel_eus:9.4::baseos",
		"cpe:/o:redhat:rhel_eus:9.6::baseos",
		"cpe:/o:redhat:rhel_eus:9.8::baseos"
	]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &fakeCommandRunner{output: []byte("bash\t0\t5.1.8\t6.el9_4\tx86_64\n")}
	output := filepath.Join(dir, "catalog.json")
	err = Generate(context.Background(), GenerateOptions{
		RHELVersion: "9", TargetReleaseVersion: "9.4", Architecture: "x86_64", RepositoryIDs: []string{"eus-baseos"},
		OutputPath: output, MappingFile: mappingPath, CommandRunner: runner,
		DNF: DNFOptions{
			Path: "dnf", InstallRoot: "/target", ScratchDir: scratchDir, ReleaseVersion: "9.4",
			RepoDirs: []string{"/target/etc/yum.repos.d"}, Architectures: []string{"x86_64", "noarch"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := OpenJSONReader(output)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	matches, err := reader.Lookup(context.Background(), NEVRA{
		Name: "bash", Epoch: "0", Version: "5.1.8", Release: "6.el9_4", Arch: "x86_64",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0] != (Match{RepositoryID: "eus-baseos", CPE: "cpe:/o:redhat:rhel_eus:9.4::baseos"}) {
		t.Fatalf("target 9.4 package CPE matches = %#v, want only the RHEL 9.4 EUS CPE", matches)
	}
}

func TestGenerateRejectsEUSMappingWithoutTargetReleaseCPE(t *testing.T) {
	dir := t.TempDir()
	mappingPath := filepath.Join(dir, "mapping.json")
	if err := os.WriteFile(mappingPath, []byte(`{"data":{"eus-baseos":{"cpes":[
		"cpe:/o:redhat:enterprise_linux:9::baseos",
		"cpe:/o:redhat:rhel_eus:9.0::baseos",
		"cpe:/o:redhat:rhel_eus:9.2::baseos",
		"cpe:/o:redhat:rhel_eus:9.4::baseos",
		"cpe:/o:redhat:rhel_eus:9.6::baseos",
		"cpe:/o:redhat:rhel_eus:9.8::baseos"
	]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &fakeCommandRunner{output: []byte("bash\t0\t5.1.8\t6.el9_7\tx86_64\n")}
	output := filepath.Join(dir, "catalog.json")
	err := Generate(context.Background(), GenerateOptions{
		RHELVersion: "9", TargetReleaseVersion: "9.7", Architecture: "x86_64", RepositoryIDs: []string{"eus-baseos"},
		OutputPath: output, MappingFile: mappingPath, CommandRunner: runner,
	})
	if err == nil {
		t.Fatal("Generate accepted a multi-minor EUS mapping without the target release CPE")
	}
	if len(runner.args) != 0 {
		t.Fatalf("DNF was queried despite the missing target CPE: %#v", runner.args)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatalf("catalog was written despite the missing target CPE: %v", err)
	}
}

func TestGenerateRejectsUnqualifiedEUSCPEForMinorTarget(t *testing.T) {
	dir := t.TempDir()
	mappingPath := filepath.Join(dir, "mapping.json")
	if err := os.WriteFile(mappingPath, []byte(`{"data":{"eus-baseos":{"cpes":["cpe:/o:redhat:rhel_eus:9::baseos"]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &fakeCommandRunner{output: []byte("bash\t0\t5.1.8\t6.el9_4\tx86_64\n")}
	output := filepath.Join(dir, "catalog.json")
	err := Generate(context.Background(), GenerateOptions{
		RHELVersion: "9", TargetReleaseVersion: "9.4", Architecture: "x86_64",
		RepositoryIDs: []string{"eus-baseos"}, OutputPath: output, MappingFile: mappingPath, CommandRunner: runner,
	})
	if err == nil {
		t.Fatal("Generate accepted a major-only EUS CPE for a minor target")
	}
	if len(runner.args) != 0 {
		t.Fatalf("DNF was queried despite the unqualified EUS CPE: %#v", runner.args)
	}
}

func TestGenerateRejectsEUSRepositoryWithoutEUSCPE(t *testing.T) {
	dir := t.TempDir()
	repositoryID := "rhel-9-for-x86_64-baseos-eus-rpms"
	mappingPath := filepath.Join(dir, "mapping.json")
	if err := os.WriteFile(mappingPath, []byte(`{"data":{"rhel-9-for-x86_64-baseos-eus-rpms":{"cpes":["cpe:/o:redhat:enterprise_linux:9::baseos"]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &fakeCommandRunner{output: []byte("bash\t0\t5.1.8\t6.el9_4\tx86_64\n")}
	output := filepath.Join(dir, "catalog.json")
	err := Generate(context.Background(), GenerateOptions{
		RHELVersion: "9", TargetReleaseVersion: "9.4", Architecture: "x86_64",
		RepositoryIDs: []string{repositoryID}, OutputPath: output, MappingFile: mappingPath, CommandRunner: runner,
	})
	if err == nil {
		t.Fatal("Generate accepted a mainline-only mapping for an EUS repository")
	}
	if len(runner.args) != 0 {
		t.Fatalf("DNF was queried despite the missing EUS CPE: %#v", runner.args)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatalf("catalog was written despite the missing EUS CPE: %v", err)
	}
}

func TestGenerateRejectsMajorOnlyTargetReleaseForEUSCPE(t *testing.T) {
	dir := t.TempDir()
	repositoryID := "rhel-9-for-x86_64-baseos-eus-rpms"
	mappingPath := filepath.Join(dir, "mapping.json")
	if err := os.WriteFile(mappingPath, []byte(`{"data":{"rhel-9-for-x86_64-baseos-eus-rpms":{"cpes":["cpe:/o:redhat:rhel_eus:9::baseos"]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &fakeCommandRunner{output: []byte("bash\t0\t5.1.8\t6.el9\tx86_64\n")}
	output := filepath.Join(dir, "catalog.json")
	err := Generate(context.Background(), GenerateOptions{
		RHELVersion: "9", TargetReleaseVersion: "9", Architecture: "x86_64",
		RepositoryIDs: []string{repositoryID}, OutputPath: output, MappingFile: mappingPath, CommandRunner: runner,
	})
	if err == nil {
		t.Fatal("Generate accepted a major-only target release for EUS CPE selection")
	}
	if len(runner.args) != 0 {
		t.Fatalf("DNF was queried despite the missing target minor: %#v", runner.args)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatalf("catalog was written despite the missing target minor: %v", err)
	}
}

func TestCPESForRHELReleaseLeavesNonEUSRepositoryUnchanged(t *testing.T) {
	cpes := []string{"cpe:/o:redhat:enterprise_linux:9::baseos"}
	got, err := cpesForRHELRelease("rhel-9-for-x86_64-baseos-rpms", cpes, "9")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, cpes) {
		t.Fatalf("non-EUS repository CPEs = %#v, want unchanged %#v", got, cpes)
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

func TestGenerateRejectsDNFArchitectureMismatch(t *testing.T) {
	dir := t.TempDir()
	mappingPath := filepath.Join(dir, "mapping.json")
	if err := os.WriteFile(mappingPath, []byte(`{"data":{"repo":{"cpes":["cpe:/o:redhat:enterprise_linux:10"]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "catalog.json")
	runner := &fakeCommandRunner{output: []byte("bash\t0\t5.1.8\t6.el10\tx86_64\n")}
	err := Generate(context.Background(), GenerateOptions{
		RHELVersion: "10", Architecture: "x86_64", RepositoryIDs: []string{"repo"},
		OutputPath: output, MappingFile: mappingPath, CommandRunner: runner,
		DNF: DNFOptions{
			Path: "dnf", InstallRoot: "/target", ScratchDir: dir, ReleaseVersion: "10.2",
			Architecture: "aarch64", RepoDirs: []string{"/target/etc/yum.repos.d"},
			Architectures: []string{"aarch64", "noarch"},
		},
	})
	if err == nil {
		t.Fatal("Generate accepted conflicting DNF and metadata architectures")
	}
	if len(runner.args) != 0 {
		t.Fatalf("Generate queried DNF before rejecting architecture mismatch: %#v", runner.args)
	}
	if _, statErr := os.Stat(output); !os.IsNotExist(statErr) {
		t.Fatalf("Generate wrote output before rejecting architecture mismatch: %v", statErr)
	}
}

func TestGenerateNormalizesRHELVersion(t *testing.T) {
	dir := t.TempDir()
	scratchDir, err := os.MkdirTemp(dir, "dnf-scratch-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(scratchDir, 0o700); err != nil {
		t.Fatal(err)
	}
	mappingPath := filepath.Join(dir, "mapping.json")
	if err := os.WriteFile(mappingPath, []byte(`{"data":{"repo":{"cpes":["cpe:/o:redhat:enterprise_linux:10"]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "catalog.json")
	runner := &fakeCommandRunner{output: []byte("bash\t0\t5.1.8\t6.el10\tx86_64\n")}
	err = Generate(context.Background(), GenerateOptions{
		RHELVersion: "10.2", Architecture: "x86_64", RepositoryIDs: []string{"repo"},
		OutputPath: output, MappingFile: mappingPath, CommandRunner: runner,
		DNF: DNFOptions{
			Path: "dnf", InstallRoot: "/target", ScratchDir: scratchDir, ReleaseVersion: "10.2",
			RepoDirs: []string{"/target/etc/yum.repos.d"}, Architectures: []string{"x86_64", "noarch"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.args) != 1 {
		t.Fatalf("DNF query count = %d, want one repository query", len(runner.args))
	}
	if !slices.Contains(runner.args[0], "--releasever=10.2") || !slices.Contains(runner.args[0], "--forcearch=x86_64") {
		t.Fatalf("DNF release version changed: %#v", runner.args[0])
	}
	reader, err := OpenJSONReader(output)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	metadata, err := reader.Metadata(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if metadata.RHELVersion != "10" {
		t.Fatalf("metadata RHEL version = %q, want major version 10", metadata.RHELVersion)
	}
}
