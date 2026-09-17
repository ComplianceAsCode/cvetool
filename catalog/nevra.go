package catalog

import (
	"fmt"
	"strings"

	claircore "github.com/quay/claircore"
)

type NEVRA struct {
	Name    string
	Epoch   string
	Version string
	Release string
	Arch    string
}

// ParsePackage mirrors Claircore's internal EVR parsing because that package is
// not importable from cvetool under Go's internal package rule. See the design
// document's "NEVRA Parsing Decision" section for the dependency rationale.
func ParsePackage(pkg *claircore.Package) (NEVRA, error) {
	if pkg == nil {
		return NEVRA{}, fmt.Errorf("nil package")
	}
	if pkg.Name == "" {
		return NEVRA{}, fmt.Errorf("empty package name")
	}
	if pkg.Arch == "" {
		return NEVRA{}, fmt.Errorf("empty package architecture")
	}
	nevra, err := parseEVR(pkg.Version)
	if err != nil {
		return NEVRA{}, err
	}
	nevra.Name = pkg.Name
	nevra.Arch = pkg.Arch
	return nevra, validateNEVRA(nevra)
}

func ParseDNFRow(row string) (NEVRA, error) {
	fields := strings.Split(row, "\t")
	if len(fields) != 5 {
		return NEVRA{}, fmt.Errorf("invalid DNF row: expected 5 tab-separated fields")
	}
	nevra := NEVRA{
		Name: fields[0], Epoch: fields[1], Version: fields[2], Release: fields[3], Arch: fields[4],
	}
	if nevra.Epoch == "" {
		nevra.Epoch = "0"
	}
	return nevra, validateNEVRA(nevra)
}

func (n NEVRA) Key() string {
	return strings.Join([]string{n.Name, n.Epoch, n.Version, n.Release, n.Arch}, "|")
}

func parseEVR(evr string) (NEVRA, error) {
	if evr == "" {
		return NEVRA{}, fmt.Errorf("empty package version")
	}
	separator := strings.LastIndexByte(evr, '-')
	if separator <= 0 || separator == len(evr)-1 {
		return NEVRA{}, fmt.Errorf("invalid package EVR %q", evr)
	}
	version := evr[:separator]
	release := evr[separator+1:]
	epoch := "0"
	if index := strings.IndexByte(version, ':'); index >= 0 {
		if index == 0 || index == len(version)-1 {
			return NEVRA{}, fmt.Errorf("invalid package EVR %q", evr)
		}
		epoch, version = version[:index], version[index+1:]
	}
	return NEVRA{Epoch: epoch, Version: version, Release: release}, nil
}

func validateNEVRA(n NEVRA) error {
	if n.Name == "" || n.Version == "" || n.Release == "" || n.Arch == "" {
		return fmt.Errorf("incomplete NEVRA")
	}
	if n.Epoch == "" {
		return fmt.Errorf("empty NEVRA epoch")
	}
	return nil
}
