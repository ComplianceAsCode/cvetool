package catalog

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"sort"
	"strings"
)

type CommandRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type execCommandRunner struct{}

func (execCommandRunner) Run(ctx context.Context, path string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, path, args...).Output()
}

const dnfQueryFormat = "%{name}\\t%{epoch}\\t%{version}\\t%{release}\\t%{arch}"

func QueryDNF(ctx context.Context, runner CommandRunner, dnfPath, repositoryID, architecture string) ([]NEVRA, error) {
	if runner == nil {
		runner = execCommandRunner{}
	}
	output, err := runner.Run(ctx, dnfPath, "--quiet", "--repo="+repositoryID, "--arch="+architecture, "repoquery", "--qf", dnfQueryFormat)
	if err != nil {
		return nil, fmt.Errorf("query repository %q: %w", repositoryID, err)
	}
	unique := map[string]NEVRA{}
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		pkg, err := ParseDNFRow(scanner.Text())
		if err != nil {
			return nil, fmt.Errorf("repository %q: %w", repositoryID, err)
		}
		unique[pkg.Key()] = pkg
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	packages := make([]NEVRA, 0, len(unique))
	for _, pkg := range unique {
		packages = append(packages, pkg)
	}
	sort.Slice(packages, func(i, j int) bool { return packages[i].Key() < packages[j].Key() })
	return packages, nil
}
