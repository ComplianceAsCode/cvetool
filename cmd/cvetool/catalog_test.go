package main

import (
	"bytes"
	"strings"
	"testing"

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
		"--repo-cpe-mapping-file",
		"--repo-cpe-mapping-url",
	} {
		if !strings.Contains(output.String(), flag) {
			t.Errorf("help output does not contain %q:\n%s", flag, output.String())
		}
	}
}

func TestCatalogCommandRequiresInputs(t *testing.T) {
	for name, args := range map[string][]string{
		"version":      {"catalog", "--arch", "x86_64", "--repo-id", "repo", "--output", "catalog.json"},
		"architecture": {"catalog", "--rhel-version", "9", "--repo-id", "repo", "--output", "catalog.json"},
		"repository":   {"catalog", "--rhel-version", "9", "--arch", "x86_64", "--output", "catalog.json"},
		"output":       {"catalog", "--rhel-version", "9", "--arch", "x86_64", "--repo-id", "repo"},
	} {
		t.Run(name, func(t *testing.T) {
			app := cli.NewApp()
			app.Commands = []*cli.Command{catalogCmd}
			err := app.Run(append([]string{"cvetool"}, args...))
			if err == nil {
				t.Fatal("catalog command accepted incomplete input")
			}
			if !strings.Contains(err.Error(), "required") {
				t.Fatalf("expected validation error, got %v", err)
			}
		})
	}
}
