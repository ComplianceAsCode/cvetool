package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ComplianceAsCode/cvetool/catalog"
	"github.com/quay/claircore/libindex"
	"github.com/quay/claircore/rhel"
	"github.com/quay/zlog"
)

type scanCatalogOptions struct {
	ExplicitPath string
	TargetRoot   string
	TargetInfo   catalog.TargetInfo
	DNF          catalog.DNFOptions
	MappingFile  string
	MappingURL   string
	Runner       catalog.CommandRunner
}

type scanCatalog struct {
	Reader         catalog.Reader
	tempDir        string
	mappingPath    string
	mappingCleanup func()
}

func prepareScanCatalogForSource(ctx context.Context, options scanCatalogOptions, imagePath, imageRef string) (*scanCatalog, error) {
	if options.ExplicitPath != "" {
		return prepareScanCatalog(ctx, options)
	}
	if imagePath != "" || imageRef != "" {
		return nil, nil
	}

	root, targetInfo, isRHEL, err := resolveScanCatalogTarget(ctx, options.TargetRoot, options.Runner)
	if err != nil {
		return nil, err
	}
	if !isRHEL {
		return nil, nil
	}
	options.TargetRoot = root
	options.TargetInfo = targetInfo
	return prepareScanCatalog(ctx, options)
}

func resolveScanCatalogTarget(ctx context.Context, root string, runner catalog.CommandRunner) (string, catalog.TargetInfo, bool, error) {
	if strings.TrimSpace(root) == "" {
		return "", catalog.TargetInfo{}, false, fmt.Errorf("target root is required")
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return "", catalog.TargetInfo{}, false, fmt.Errorf("resolve target root: %w", err)
	}
	targetRoot, err := os.OpenRoot(root)
	if err != nil {
		return "", catalog.TargetInfo{}, false, fmt.Errorf("open target root: %w", err)
	}
	defer targetRoot.Close()
	osRelease, err := targetRoot.ReadFile("etc/os-release")
	if errors.Is(err, os.ErrNotExist) {
		return root, catalog.TargetInfo{}, false, nil
	}
	if err != nil {
		return "", catalog.TargetInfo{}, false, fmt.Errorf("read target os-release: %w", err)
	}
	isRHEL, err := targetHasRHELID(osRelease)
	if err != nil {
		return "", catalog.TargetInfo{}, false, err
	}
	if !isRHEL {
		return root, catalog.TargetInfo{}, false, nil
	}

	installedArchitectures, err := catalog.QueryInstalledRPMArchitectures(ctx, runner, "rpm", root)
	if err != nil {
		return "", catalog.TargetInfo{}, false, fmt.Errorf("query target RPM architectures: %w", err)
	}
	architectures, err := catalog.ResolveTargetArchitecture(installedArchitectures)
	if err != nil {
		return "", catalog.TargetInfo{}, false, fmt.Errorf("resolve target RPM architectures: %w", err)
	}
	targetInfo, err := catalog.ResolveTargetInfo(osRelease, "", architectures)
	if err != nil {
		return "", catalog.TargetInfo{}, false, fmt.Errorf("resolve target RHEL metadata: %w", err)
	}
	releaseVersion, err := catalog.ResolveTargetReleaseVersion(root, targetInfo.ReleaseVersion)
	if err != nil {
		return "", catalog.TargetInfo{}, false, fmt.Errorf("resolve target release version: %w", err)
	}
	targetInfo, err = catalog.ResolveTargetInfo(osRelease, releaseVersion, architectures)
	if err != nil {
		return "", catalog.TargetInfo{}, false, fmt.Errorf("resolve target RHEL metadata: %w", err)
	}
	return root, targetInfo, true, nil
}

func targetHasRHELID(osRelease []byte) (bool, error) {
	scanner := bufio.NewScanner(strings.NewReader(string(osRelease)))
	id := ""
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(key) != "ID" {
			continue
		}
		value = strings.TrimSpace(value)
		if value != "" {
			quote := value[0]
			if quote == '"' || quote == '\'' {
				if len(value) < 2 || value[len(value)-1] != quote {
					return false, fmt.Errorf("parse target os-release ID: unmatched quote")
				}
				value = value[1 : len(value)-1]
			} else if value[len(value)-1] == '"' || value[len(value)-1] == '\'' {
				return false, fmt.Errorf("parse target os-release ID: unmatched quote")
			}
		}
		id = value
	}
	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("read target os-release: %w", err)
	}
	return id == "rhel", nil
}

func prepareScanCatalog(ctx context.Context, options scanCatalogOptions) (result *scanCatalog, retErr error) {
	prepared := &scanCatalog{}
	defer func() {
		if retErr != nil {
			retErr = errors.Join(retErr, prepared.Close())
		}
	}()

	if options.ExplicitPath != "" {
		reader, err := catalog.OpenJSONReader(options.ExplicitPath)
		if err != nil {
			return nil, fmt.Errorf("open explicit catalog: %w", err)
		}
		prepared.Reader = reader
		if _, err := reader.Metadata(ctx); err != nil {
			return nil, fmt.Errorf("read explicit catalog metadata: %w", err)
		}
	} else {
		if strings.TrimSpace(options.TargetRoot) == "" {
			return nil, fmt.Errorf("target root is required")
		}
		if options.TargetInfo.RHELVersion == "" || options.TargetInfo.ReleaseVersion == "" || options.TargetInfo.Architecture == "" || len(options.TargetInfo.Architectures) == 0 {
			return nil, fmt.Errorf("target RHEL metadata is incomplete")
		}
		root, err := filepath.Abs(options.TargetRoot)
		if err != nil {
			return nil, fmt.Errorf("resolve target root: %w", err)
		}
		tempDir, err := os.MkdirTemp(os.TempDir(), "cvetool-scan-*")
		if err != nil {
			return nil, fmt.Errorf("create scan catalog directory: %w", err)
		}
		prepared.tempDir = tempDir
		prepared.tempDir, err = filepath.Abs(prepared.tempDir)
		if err != nil {
			return nil, fmt.Errorf("resolve scan catalog directory: %w", err)
		}

		repoDirs, err := catalog.ResolveTargetRepoDirs(root)
		if err != nil {
			return nil, fmt.Errorf("resolve target repository directories: %w", err)
		}
		dnf := options.DNF
		if strings.TrimSpace(dnf.Path) == "" {
			dnf.Path = "dnf"
		}
		dnf.InstallRoot = root
		dnf.ScratchDir = prepared.tempDir
		dnf.ReleaseVersion = options.TargetInfo.ReleaseVersion
		dnf.Architecture = options.TargetInfo.Architecture
		dnf.RepoDirs = repoDirs
		dnf.Architectures = options.TargetInfo.Architectures

		enabled, err := catalog.EnabledRepositories(ctx, options.Runner, dnf)
		if err != nil {
			return nil, fmt.Errorf("discover enabled target repositories: %w", err)
		}
		mapping, err := catalog.LoadRepositoryMapping(ctx, options.MappingFile, options.MappingURL)
		if err != nil {
			return nil, err
		}
		selection, selectionErr := catalog.SelectMappedRepositories(mapping, enabled)
		for _, id := range selection.Skipped {
			zlog.Warn(ctx).Str("repository_id", id).Msg("skipping enabled target repository without a CPE mapping")
		}
		if selectionErr != nil {
			return nil, selectionErr
		}
		catalogPath := filepath.Join(prepared.tempDir, "catalog.json")
		if err := catalog.Generate(ctx, catalog.GenerateOptions{
			RHELVersion:   options.TargetInfo.RHELVersion,
			Architecture:  options.TargetInfo.Architecture,
			RepositoryIDs: selection.Mapped,
			OutputPath:    catalogPath,
			MappingFile:   options.MappingFile,
			MappingURL:    options.MappingURL,
			DNF:           dnf,
			CommandRunner: options.Runner,
		}); err != nil {
			return nil, fmt.Errorf("generate target catalog: %w", err)
		}
		reader, err := catalog.OpenJSONReader(catalogPath)
		if err != nil {
			return nil, fmt.Errorf("open generated catalog: %w", err)
		}
		prepared.Reader = reader
		if _, err := reader.Metadata(ctx); err != nil {
			return nil, fmt.Errorf("read generated catalog metadata: %w", err)
		}
	}

	if err := prepared.prepareRepositoryMapping(); err != nil {
		return nil, err
	}
	return prepared, nil
}

func (s *scanCatalog) prepareRepositoryMapping() error {
	path, cleanup, err := s.Reader.RepositoryMappingFile()
	if cleanup != nil {
		s.mappingCleanup = cleanup
	}
	if err != nil {
		return fmt.Errorf("create catalog repository mapping: %w", err)
	}
	s.mappingPath = path
	return nil
}

func (s *scanCatalog) configureScanner(options *libindex.Options) error {
	if s == nil || s.Reader == nil || s.mappingPath == "" {
		return fmt.Errorf("scan catalog is not ready for scanner configuration")
	}
	if options.ScannerConfig.Repo == nil {
		options.ScannerConfig.Repo = map[string]func(any) error{}
	}
	options.ScannerConfig.Repo["rhel-repository-scanner"] = func(value any) error {
		config, ok := value.(*rhel.RepositoryScannerConfig)
		if !ok {
			return fmt.Errorf("expected *rhel.RepositoryScannerConfig, got %T", value)
		}
		config.Repo2CPEMappingFile = s.mappingPath
		config.Repo2CPEMappingURL = ""
		return nil
	}
	return nil
}

func (s *scanCatalog) Close() error {
	if s == nil {
		return nil
	}
	var closeErrors []error
	if s.Reader != nil {
		closeErrors = append(closeErrors, s.Reader.Close())
		s.Reader = nil
	}
	if s.mappingCleanup != nil {
		s.mappingCleanup()
		s.mappingCleanup = nil
	}
	if s.mappingPath != "" {
		if err := os.Remove(s.mappingPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			closeErrors = append(closeErrors, fmt.Errorf("remove temporary catalog mapping: %w", err))
		}
	}
	s.mappingPath = ""
	if s.tempDir != "" {
		if err := os.RemoveAll(s.tempDir); err != nil {
			closeErrors = append(closeErrors, fmt.Errorf("remove scan catalog directory: %w", err))
		}
		s.tempDir = ""
	}
	return errors.Join(closeErrors...)
}

func closeScanCatalog(scanErr error, prepared *scanCatalog) error {
	if prepared == nil {
		return scanErr
	}
	if closeErr := prepared.Close(); closeErr != nil {
		return errors.Join(scanErr, fmt.Errorf("error closing scan catalog: %w", closeErr))
	}
	return scanErr
}
