package catalog

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestResolveTargetArchitectureIncludesMultilib(t *testing.T) {
	got, err := ResolveTargetArchitecture([]string{"x86_64", "i686", "noarch"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Primary != "x86_64" || !slices.Equal(got.Packages, []string{"i686", "noarch", "x86_64"}) {
		t.Fatalf("resolved architecture = %#v", got)
	}
}

func TestResolveTargetArchitectureSelectsSupportedFamilies(t *testing.T) {
	for _, test := range []struct {
		name          string
		architectures []string
		primary       string
		packages      []string
	}{
		{name: "aarch64 multilib", architectures: []string{"aarch64", "armv7hl", "noarch"}, primary: "aarch64", packages: []string{"aarch64", "armv7hl", "noarch"}},
		{name: "standalone i686", architectures: []string{"i686"}, primary: "i686", packages: []string{"i686", "noarch"}},
		{name: "standalone ppc64le", architectures: []string{"ppc64le"}, primary: "ppc64le", packages: []string{"noarch", "ppc64le"}},
		{name: "standalone s390x", architectures: []string{"s390x"}, primary: "s390x", packages: []string{"noarch", "s390x"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := ResolveTargetArchitecture(test.architectures)
			if err != nil {
				t.Fatal(err)
			}
			if got.Primary != test.primary || !slices.Equal(got.Packages, test.packages) {
				t.Fatalf("resolved architecture = %#v, want primary %q and packages %v", got, test.primary, test.packages)
			}
		})
	}
}

func TestResolveTargetArchitectureRejectsEmptyAndAmbiguousSets(t *testing.T) {
	for _, test := range []struct {
		name          string
		architectures []string
	}{
		{name: "empty", architectures: nil},
		{name: "noarch only", architectures: []string{"noarch"}},
		{name: "mixed native families", architectures: []string{"x86_64", "aarch64"}},
		{name: "unsupported architecture", architectures: []string{"armv7hl"}},
		{name: "ambiguous 32-bit x86", architectures: []string{"i686", "i586"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ResolveTargetArchitecture(test.architectures); err == nil {
				t.Fatal("ResolveTargetArchitecture succeeded")
			}
		})
	}
}

func TestSelectMappedRepositories(t *testing.T) {
	mapping := RepositoryMapping{data: map[string][]string{
		"mapped-repo": {"cpe:/o:redhat:enterprise_linux:10"},
	}}

	t.Run("skips unmapped enabled repositories", func(t *testing.T) {
		got, err := SelectMappedRepositories(mapping, []string{"z-unmapped", "mapped-repo", "a-unmapped"})
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(got.Mapped, []string{"mapped-repo"}) || !slices.Equal(got.Skipped, []string{"a-unmapped", "z-unmapped"}) {
			t.Fatalf("repository selection = %#v", got)
		}
	})

	t.Run("rejects when no enabled repository is mapped", func(t *testing.T) {
		got, err := SelectMappedRepositories(mapping, []string{"a-unmapped", "z-unmapped"})
		if err == nil {
			t.Fatal("SelectMappedRepositories accepted an empty mapped set")
		}
		if !slices.Equal(got.Skipped, []string{"a-unmapped", "z-unmapped"}) {
			t.Fatalf("unmapped repositories were not returned with the error: %#v", got)
		}
	})
}

func TestResolveTargetInfoUsesRHELMajorAndFullReleaseVersion(t *testing.T) {
	got, err := ResolveTargetInfo(
		[]byte("ID=\"rhel\"\nVERSION_ID=\"10.2\"\n"),
		"",
		ArchitectureSet{Primary: "x86_64", Packages: []string{"i686", "noarch", "x86_64"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	wantArchitectures := []string{"i686", "noarch", "x86_64"}
	if got.RHELVersion != "10" || got.ReleaseVersion != "10.2" || got.Architecture != "x86_64" || !slices.Equal(got.Architectures, wantArchitectures) {
		t.Fatalf("target info = %#v", got)
	}
}

func TestResolveTargetInfoRetainsMajorAndExplicitReleaseVersion(t *testing.T) {
	got, err := ResolveTargetInfo(
		[]byte("ID=rhel\nVERSION_ID=9.6\n"),
		"9.7",
		ArchitectureSet{Primary: "s390x", Packages: []string{"noarch", "s390x"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got.RHELVersion != "9" || got.ReleaseVersion != "9.7" {
		t.Fatalf("target release = RHEL %q, DNF %q", got.RHELVersion, got.ReleaseVersion)
	}
}

func TestResolveTargetInfoRejectsNonRHELIdentity(t *testing.T) {
	_, err := ResolveTargetInfo(
		[]byte("ID=fedora\nVERSION_ID=40\n"),
		"",
		ArchitectureSet{Primary: "x86_64", Packages: []string{"noarch", "x86_64"}},
	)
	if err == nil {
		t.Fatal("ResolveTargetInfo accepted a non-RHEL target")
	}
}

func TestResolveTargetInfoRejectsInvalidArchitectureSet(t *testing.T) {
	_, err := ResolveTargetInfo(
		[]byte("ID=rhel\nVERSION_ID=10.2\n"),
		"",
		ArchitectureSet{Primary: "x86_64", Packages: []string{"aarch64", "x86_64"}},
	)
	if err == nil {
		t.Fatal("ResolveTargetInfo accepted an ambiguous architecture set")
	}
}

func TestResolveTargetReleaseVersionUsesTargetOverrides(t *testing.T) {
	for _, test := range []struct {
		name      string
		files     map[string]string
		versionID string
		want      string
	}{
		{name: "dnf override", files: map[string]string{"etc/dnf/vars/releasever": "10.4\n"}, versionID: "10.2", want: "10.4"},
		{name: "yum override", files: map[string]string{"etc/yum/vars/releasever": "9.7\n"}, versionID: "9.6", want: "9.7"},
		{name: "version ID fallback", versionID: "10.2", want: "10.2"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			for path, content := range test.files {
				writeTargetFile(t, root, path, content)
			}
			got, err := ResolveTargetReleaseVersion(root, test.versionID)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("release version = %q, want %q", got, test.want)
			}
		})
	}
}

func TestResolveTargetReleaseVersionPrefersDNFOverride(t *testing.T) {
	root := t.TempDir()
	writeTargetFile(t, root, "etc/dnf/vars/releasever", "10.4\n")
	writeTargetFile(t, root, "etc/yum/vars/releasever", "10.3\n")

	got, err := ResolveTargetReleaseVersion(root, "10.2")
	if err != nil {
		t.Fatal(err)
	}
	if got != "10.4" {
		t.Fatalf("release version = %q, want %q", got, "10.4")
	}
}

func TestResolveTargetRepoDirsDefaultsToTargetYumRepoDir(t *testing.T) {
	root := t.TempDir()
	got, err := ResolveTargetRepoDirs(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{filepath.Join(root, "etc", "yum.repos.d")}
	if !slices.Equal(got, want) {
		t.Fatalf("repository directories = %v, want %v", got, want)
	}
}

func TestResolveTargetRepoDirsRootsConfiguredPathsUnderTarget(t *testing.T) {
	root := t.TempDir()
	writeTargetFile(t, root, "etc/dnf/dnf.conf", "[main]\nreposdir=/etc/custom-repos.d,/opt/target-repos\n")

	got, err := ResolveTargetRepoDirs(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		filepath.Join(root, "etc", "custom-repos.d"),
		filepath.Join(root, "opt", "target-repos"),
	}
	if !slices.Equal(got, want) {
		t.Fatalf("repository directories = %v, want %v", got, want)
	}
}

func TestResolveTargetRepoDirsRejectsPathsOutsideTarget(t *testing.T) {
	root := t.TempDir()
	writeTargetFile(t, root, "etc/dnf/dnf.conf", "[main]\nreposdir=../../outside/repos\n")
	if _, err := ResolveTargetRepoDirs(root); err == nil {
		t.Fatal("ResolveTargetRepoDirs accepted a path outside the target root")
	}
}

func TestResolveTargetRepoDirsRejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "external-repos")); err != nil {
		t.Fatal(err)
	}
	writeTargetFile(t, root, "etc/dnf/dnf.conf", "[main]\nreposdir=/external-repos\n")

	if _, err := ResolveTargetRepoDirs(root); err == nil {
		t.Fatal("ResolveTargetRepoDirs accepted a repository directory outside the target root")
	}
}

func TestResolveTargetRepoDirsRejectsDefaultSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "etc", "yum.repos.d")); err != nil {
		t.Fatal(err)
	}

	if _, err := ResolveTargetRepoDirs(root); err == nil {
		t.Fatal("ResolveTargetRepoDirs accepted a default repository directory outside the target root")
	}
}

func TestQueryInstalledRPMArchitecturesUsesTargetRootAndExcludesSourceAndPlaceholderArchitectures(t *testing.T) {
	runner := &fakeCommandRunner{output: []byte("(none)\nx86_64\n(none)\ni686\nnoarch\nsrc\nnosrc\nx86_64\n(none)\n")}
	got, err := QueryInstalledRPMArchitectures(context.Background(), runner, "rpm", "/target")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"i686", "noarch", "x86_64"}
	if !slices.Equal(got, want) {
		t.Fatalf("RPM architectures = %v, want %v", got, want)
	}
	wantCommand := []string{"rpm", "--root=/target", "--query", "--all", "--queryformat=%{ARCH}\\n"}
	if len(runner.args) != 1 || !slices.Equal(runner.args[0], wantCommand) {
		t.Fatalf("RPM command = %#v, want %#v", runner.args, [][]string{wantCommand})
	}
}

func TestQueryInstalledRPMArchitecturesReturnsCommandErrors(t *testing.T) {
	commandErr := errors.New("rpm failed")
	_, err := QueryInstalledRPMArchitectures(context.Background(), &fakeCommandRunner{err: commandErr}, "rpm", "/target")
	if !errors.Is(err, commandErr) {
		t.Fatalf("query error = %v, want wrapped %v", err, commandErr)
	}
}

func TestQueryInstalledRPMArchitecturesRequiresTargetRoot(t *testing.T) {
	runner := &fakeCommandRunner{output: []byte("x86_64\n")}
	if _, err := QueryInstalledRPMArchitectures(context.Background(), runner, "rpm", ""); err == nil {
		t.Fatal("QueryInstalledRPMArchitectures succeeded without a target root")
	}
	if len(runner.args) != 0 {
		t.Fatalf("RPM command ran without a target root: %#v", runner.args)
	}
}

func writeTargetFile(t *testing.T, root, path, content string) {
	t.Helper()
	fullPath := filepath.Join(root, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fullPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
