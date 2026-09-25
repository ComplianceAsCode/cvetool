package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ComplianceAsCode/cvetool/catalog"
	"github.com/urfave/cli/v2"
)

func TestCatalogCommandHelp(t *testing.T) {
	var output bytes.Buffer
	app := cli.NewApp()
	app.Writer = &output
	app.Commands = []*cli.Command{catalogCmd}

	if err := app.Run([]string{"cvetool", "catalog", "--help"}); err != nil {
		t.Fatal(err)
	}
	for _, flag := range []string{
		"--rhel-version",
		"--arch",
		"--repo-id",
		"--output",
		"--dnf-path",
		"--repo-cpe-mapping-file",
		"--repo-cpe-mapping-url",
	} {
		if !strings.Contains(output.String(), flag) {
			t.Errorf("help output does not contain %q:\n%s", flag, output.String())
		}
	}
}

func TestCatalogCommandRequiresOutput(t *testing.T) {
	app := cli.NewApp()
	app.Commands = []*cli.Command{catalogCmd}
	err := app.Run([]string{"cvetool", "catalog", "--rhel-version", "9", "--arch", "x86_64", "--repo-id", "repo"})
	if err == nil {
		t.Fatal("catalog command accepted a missing output path")
	}
	if !strings.Contains(err.Error(), "required") {
		t.Fatalf("expected output validation error, got %v", err)
	}
}

func TestResolveCatalogInputsFullyExplicitSkipsDiscovery(t *testing.T) {
	runner := &catalogInputCommandRunner{}
	options := catalog.GenerateOptions{
		RHELVersion: "10", Architecture: "aarch64", RepositoryIDs: []string{"manual-repo"},
		OutputPath: "catalog.json", DNFPath: "/custom/dnf", CommandRunner: runner,
		DNF: catalog.DNFOptions{Architectures: []string{"aarch64", "noarch"}},
	}

	got, err := resolveCatalogInputsAtRoot(context.Background(), options, "/")
	if err != nil {
		t.Fatal(err)
	}
	if got.RHELVersion != "10" || got.Architecture != "aarch64" || !reflect.DeepEqual(got.RepositoryIDs, []string{"manual-repo"}) || got.DNFPath != "/custom/dnf" {
		t.Fatalf("resolved explicit inputs = %#v", got)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("explicit inputs triggered discovery commands: %#v", runner.calls)
	}
}

func TestResolveCatalogInputsInfersHostValuesAndSkipsUnmappedRepositories(t *testing.T) {
	root := t.TempDir()
	writeCatalogInputFile(t, root, "etc/os-release", "ID=rhel\nVERSION_ID=10.2\n")
	mappingPath := filepath.Join(t.TempDir(), "mapping.json")
	if err := os.WriteFile(mappingPath, []byte(`{"data":{"mapped-repo":{"cpes":["cpe:/o:redhat:enterprise_linux:10"]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &catalogInputCommandRunner{outputs: map[string][]byte{
		"rpm":      []byte("x86_64\ni686\nnoarch\n"),
		"/opt/dnf": []byte("repo id repo name\nmapped-repo Mapped repository\nunmapped-repo Unmapped repository\nrepolist: 1\n"),
	}}
	options := catalog.GenerateOptions{
		OutputPath: "catalog.json", MappingFile: mappingPath, DNFPath: "/opt/dnf", CommandRunner: runner,
	}

	got, err := resolveCatalogInputsAtRoot(context.Background(), options, root)
	if err != nil {
		t.Fatal(err)
	}
	if got.RHELVersion != "10" || got.Architecture != "x86_64" || !reflect.DeepEqual(got.RepositoryIDs, []string{"mapped-repo"}) {
		t.Fatalf("inferred inputs = %#v", got)
	}
	if !reflect.DeepEqual(got.DNF.Architectures, []string{"i686", "noarch", "x86_64"}) {
		t.Fatalf("package architectures = %v", got.DNF.Architectures)
	}
	wantCalls := [][]string{
		{"rpm", "--root=" + root, "--query", "--all", "--queryformat=%{ARCH}\\n"},
		{"/opt/dnf", "--quiet", "repolist", "--enabled"},
	}
	if !reflect.DeepEqual(runner.calls, wantCalls) {
		t.Fatalf("discovery commands = %#v, want %#v", runner.calls, wantCalls)
	}
}

func TestResolveCatalogInputsPreservesExplicitValuesIndividually(t *testing.T) {
	root := t.TempDir()
	writeCatalogInputFile(t, root, "etc/os-release", "ID=rhel\nVERSION_ID=10.2\n")

	t.Run("matching primary still reads RPM inventory for multilib", func(t *testing.T) {
		runner := &catalogInputCommandRunner{outputs: map[string][]byte{
			"rpm": []byte("x86_64\ni686\nnoarch\n"),
		}}
		got, err := resolveCatalogInputsAtRoot(context.Background(), catalog.GenerateOptions{
			Architecture: "x86_64", RepositoryIDs: []string{"manual-repo"}, OutputPath: "catalog.json", CommandRunner: runner,
		}, root)
		if err != nil {
			t.Fatal(err)
		}
		if got.RHELVersion != "10" || got.Architecture != "x86_64" || !reflect.DeepEqual(got.RepositoryIDs, []string{"manual-repo"}) {
			t.Fatalf("resolved inputs = %#v", got)
		}
		if !reflect.DeepEqual(got.DNF.Architectures, []string{"i686", "noarch", "x86_64"}) {
			t.Fatalf("matching explicit architecture did not retain installed multilib: %v", got.DNF.Architectures)
		}
		wantCalls := [][]string{{"rpm", "--root=" + root, "--query", "--all", "--queryformat=%{ARCH}\\n"}}
		if !reflect.DeepEqual(runner.calls, wantCalls) {
			t.Fatalf("explicit architecture discovery = %#v, want RPM inventory only %#v", runner.calls, wantCalls)
		}
	})

	t.Run("explicit version and repositories", func(t *testing.T) {
		runner := &catalogInputCommandRunner{outputs: map[string][]byte{"rpm": []byte("x86_64\ni686\n")}}
		got, err := resolveCatalogInputsAtRoot(context.Background(), catalog.GenerateOptions{
			RHELVersion: "9", RepositoryIDs: []string{"manual-repo"}, OutputPath: "catalog.json", CommandRunner: runner,
		}, root)
		if err != nil {
			t.Fatal(err)
		}
		if got.RHELVersion != "9" || got.Architecture != "x86_64" || !reflect.DeepEqual(got.RepositoryIDs, []string{"manual-repo"}) {
			t.Fatalf("resolved inputs = %#v", got)
		}
		if len(runner.calls) != 1 || runner.calls[0][0] != "rpm" {
			t.Fatalf("version/repository overrides triggered unexpected discovery: %#v", runner.calls)
		}
	})
}

func TestResolveCatalogInputsExplicitArchitectureFiltersHostArchitectures(t *testing.T) {
	root := t.TempDir()

	t.Run("same primary keeps installed multilib", func(t *testing.T) {
		runner := &catalogInputCommandRunner{outputs: map[string][]byte{
			"rpm": []byte("x86_64\ni686\nnoarch\n"),
		}}
		got, err := resolveCatalogInputsAtRoot(context.Background(), catalog.GenerateOptions{
			RHELVersion: "10", Architecture: "x86_64", RepositoryIDs: []string{"manual-repo"},
			OutputPath: "catalog.json", CommandRunner: runner,
		}, root)
		if err != nil {
			t.Fatal(err)
		}
		wantArchitectures := []string{"i686", "noarch", "x86_64"}
		if !reflect.DeepEqual(got.DNF.Architectures, wantArchitectures) {
			t.Fatalf("same-primary package architectures = %v, want %v", got.DNF.Architectures, wantArchitectures)
		}
		if len(runner.calls) != 1 || runner.calls[0][0] != "rpm" {
			t.Fatalf("same-primary resolution did not detect installed architectures: %#v", runner.calls)
		}
	})

	t.Run("different primary drops installed multilib", func(t *testing.T) {
		runner := &catalogInputCommandRunner{outputs: map[string][]byte{
			"rpm": []byte("x86_64\ni686\nnoarch\n"),
		}}
		got, err := resolveCatalogInputsAtRoot(context.Background(), catalog.GenerateOptions{
			RHELVersion: "10", Architecture: "aarch64", RepositoryIDs: []string{"manual-repo"},
			OutputPath: "catalog.json", CommandRunner: runner,
		}, root)
		if err != nil {
			t.Fatal(err)
		}
		wantArchitectures := []string{"aarch64", "noarch"}
		if !reflect.DeepEqual(got.DNF.Architectures, wantArchitectures) {
			t.Fatalf("cross-primary package architectures = %v, want %v", got.DNF.Architectures, wantArchitectures)
		}
		if len(runner.calls) != 1 || runner.calls[0][0] != "rpm" {
			t.Fatalf("cross-primary resolution did not detect installed architectures: %#v", runner.calls)
		}
	})
}

func TestResolveCatalogInputsRequiresOutput(t *testing.T) {
	runner := &catalogInputCommandRunner{}
	_, err := resolveCatalogInputsAtRoot(context.Background(), catalog.GenerateOptions{
		RHELVersion: "10", Architecture: "x86_64", RepositoryIDs: []string{"manual-repo"}, CommandRunner: runner,
	}, "/")
	if err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("missing output error = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("missing output triggered discovery commands: %#v", runner.calls)
	}
}

type catalogInputCommandRunner struct {
	outputs map[string][]byte
	calls   [][]string
}

func (r *catalogInputCommandRunner) Run(_ context.Context, path string, args ...string) ([]byte, error) {
	call := append([]string{path}, args...)
	r.calls = append(r.calls, call)
	output, ok := r.outputs[path]
	if !ok {
		return nil, errors.New("unexpected discovery command")
	}
	return output, nil
}

func writeCatalogInputFile(t *testing.T, root, path, content string) {
	t.Helper()
	fullPath := filepath.Join(root, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fullPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
