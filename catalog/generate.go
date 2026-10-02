package catalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type GenerateOptions struct {
	RHELVersion   string
	Architecture  string
	RepositoryIDs []string
	OutputPath    string
	MappingFile   string
	MappingURL    string
	DNFPath       string
	DNF           DNFOptions
	CommandRunner CommandRunner
}

func Generate(ctx context.Context, options GenerateOptions) error {
	if options.RHELVersion == "" || options.Architecture == "" || len(options.RepositoryIDs) == 0 || options.OutputPath == "" {
		return fmt.Errorf("RHEL version, architecture, repository IDs, and output path are required")
	}
	if options.DNF.Architecture != "" && options.DNF.Architecture != options.Architecture {
		return fmt.Errorf("DNF architecture %q does not match catalog architecture %q", options.DNF.Architecture, options.Architecture)
	}
	ids := append([]string(nil), options.RepositoryIDs...)
	sort.Strings(ids)
	mapping, err := LoadRepositoryMapping(ctx, options.MappingFile, options.MappingURL)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := mapping.Validate(id); err != nil {
			return err
		}
	}
	dnfOptions := options.DNF
	if options.DNFPath != "" {
		dnfOptions.Path = options.DNFPath
	}
	if dnfOptions.Path == "" {
		dnfOptions.Path = "dnf"
	}
	if dnfOptions.InstallRoot == "" {
		if dnfOptions.ScratchDir != "" || dnfOptions.ReleaseVersion != "" || dnfOptions.Architecture != "" || len(dnfOptions.RepoDirs) != 0 {
			return fmt.Errorf("target DNF install root is required")
		}
		dnfOptions.legacyHostQuery = true
		dnfOptions.Architecture = options.Architecture
		if len(dnfOptions.Architectures) != 0 {
			architectures := make([]string, 0, len(dnfOptions.Architectures))
			seen := make(map[string]struct{}, len(dnfOptions.Architectures))
			for _, architecture := range dnfOptions.Architectures {
				architecture = strings.TrimSpace(architecture)
				if architecture == "" || architecture == "noarch" {
					continue
				}
				if _, ok := seen[architecture]; ok {
					continue
				}
				seen[architecture] = struct{}{}
				architectures = append(architectures, architecture)
			}
			if len(architectures) != 0 {
				dnfOptions.Architecture = strings.Join(architectures, ",")
			}
		}
	} else if dnfOptions.Architecture == "" {
		dnfOptions.Architecture = options.Architecture
	}
	packages := make([]struct {
		id  string
		pkg NEVRA
	}, 0)
	for _, id := range ids {
		rows, err := QueryDNFWithOptions(ctx, options.CommandRunner, dnfOptions, id)
		if err != nil {
			return err
		}
		for _, pkg := range rows {
			packages = append(packages, struct {
				id  string
				pkg NEVRA
			}{id: id, pkg: pkg})
		}
	}
	sort.Slice(packages, func(i, j int) bool {
		if packages[i].id != packages[j].id {
			return packages[i].id < packages[j].id
		}
		return packages[i].pkg.Key() < packages[j].pkg.Key()
	})
	packageValues := make([]string, len(packages))
	for i, value := range packages {
		packageValues[i] = value.id + "\x00" + value.pkg.Key()
	}
	packageHash := sha256.Sum256([]byte(joinStrings(packageValues)))
	targetDir := filepath.Dir(options.OutputPath)
	temporary, err := os.CreateTemp(targetDir, ".cvetool-catalog-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	temporary.Close()
	defer os.Remove(temporaryPath)
	writer, err := NewJSONWriter(temporaryPath)
	if err != nil {
		return err
	}
	for _, id := range ids {
		cpes, _ := mapping.Lookup(id)
		if err := writer.AddRepository(Repository{ID: id, CPEs: cpes}); err != nil {
			writer.Close()
			return err
		}
	}
	for _, value := range packages {
		for _, cpe := range mustMappingLookup(mapping, value.id) {
			if err := writer.AddPackage(value.pkg, Match{RepositoryID: value.id, CPE: cpe}); err != nil {
				writer.Close()
				return err
			}
		}
	}
	rhelMajor, _, _ := strings.Cut(strings.TrimSpace(options.RHELVersion), ".")
	metadata := Metadata{SchemaVersion: "1", RHELVersion: rhelMajor, Architecture: options.Architecture, RepositoryIDs: ids, MappingSource: mapping.Source(), MappingFingerprint: mapping.Fingerprint(ids), PackageFingerprint: hex.EncodeToString(packageHash[:]), GeneratedAt: time.Now().UTC()}
	if err := writer.SetMetadata(metadata); err != nil {
		writer.Close()
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, options.OutputPath)
}

func mustMappingLookup(mapping RepositoryMapping, id string) []string {
	cpes, _ := mapping.Lookup(id)
	return cpes
}

func joinStrings(values []string) string {
	result := ""
	for _, value := range values {
		result += value + "\n"
	}
	return result
}
