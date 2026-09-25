package catalog

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type TargetInfo struct {
	RHELVersion    string
	ReleaseVersion string
	Architecture   string
	Architectures  []string
}

type ArchitectureSet struct {
	Primary  string
	Packages []string
}

type RepositorySelection struct {
	Mapped  []string
	Skipped []string
}

func SelectMappedRepositories(mapping RepositoryMapping, enabled []string) (RepositorySelection, error) {
	ids := append([]string(nil), enabled...)
	sort.Strings(ids)
	selection := RepositorySelection{}
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		if _, ok := mapping.Lookup(id); !ok {
			selection.Skipped = append(selection.Skipped, id)
			continue
		}
		if err := mapping.Validate(id); err != nil {
			return selection, err
		}
		selection.Mapped = append(selection.Mapped, id)
	}
	if len(selection.Mapped) == 0 {
		return selection, fmt.Errorf("no enabled repositories have a CPE mapping")
	}
	return selection, nil
}

func EnabledHostRepositories(ctx context.Context, runner CommandRunner, dnfPath string) ([]string, error) {
	if strings.TrimSpace(dnfPath) == "" {
		return nil, fmt.Errorf("DNF path is required")
	}
	output, err := runDNF(ctx, runner, dnfPath, "--quiet", "repolist", "--enabled")
	if err != nil {
		return nil, fmt.Errorf("list enabled host repositories: %w", err)
	}
	repositories, err := parseEnabledRepositories(output)
	if err != nil {
		return nil, fmt.Errorf("parse enabled host repositories: %w", err)
	}
	return repositories, nil
}

func ResolveTargetArchitecture(installedRPMArchitectures []string) (ArchitectureSet, error) {
	seen := make(map[string]struct{}, len(installedRPMArchitectures)+1)
	architectures := make([]string, 0, len(installedRPMArchitectures)+1)
	for _, architecture := range installedRPMArchitectures {
		architecture = strings.TrimSpace(architecture)
		if architecture == "" {
			continue
		}
		if _, ok := seen[architecture]; ok {
			continue
		}
		seen[architecture] = struct{}{}
		architectures = append(architectures, architecture)
	}
	if len(architectures) == 0 {
		return ArchitectureSet{}, fmt.Errorf("target RPM architecture inventory is empty")
	}
	sort.Strings(architectures)

	family := ""
	hasX8664, hasI686, hasI586, hasAarch64 := false, false, false, false
	for _, architecture := range architectures {
		var currentFamily string
		switch architecture {
		case "noarch":
			continue
		case "x86_64":
			currentFamily, hasX8664 = "x86", true
		case "i686":
			currentFamily, hasI686 = "x86", true
		case "i586":
			currentFamily, hasI586 = "x86", true
		case "aarch64":
			currentFamily, hasAarch64 = "arm", true
		case "armv7hl":
			currentFamily = "arm"
		case "ppc64le":
			currentFamily = "ppc64le"
		case "s390x":
			currentFamily = "s390x"
		default:
			return ArchitectureSet{}, fmt.Errorf("unsupported target RPM architecture %q", architecture)
		}
		if family != "" && family != currentFamily {
			return ArchitectureSet{}, fmt.Errorf("ambiguous target RPM architecture families")
		}
		family = currentFamily
	}

	primary := ""
	switch family {
	case "x86":
		if hasX8664 {
			primary = "x86_64"
		} else if hasI686 && !hasI586 {
			primary = "i686"
		} else {
			return ArchitectureSet{}, fmt.Errorf("ambiguous or unsupported 32-bit x86 target architectures")
		}
	case "arm":
		if hasAarch64 {
			primary = "aarch64"
		} else {
			return ArchitectureSet{}, fmt.Errorf("unsupported target RPM architecture family %q", family)
		}
	case "ppc64le", "s390x":
		primary = family
	default:
		return ArchitectureSet{}, fmt.Errorf("target RPM architecture inventory contains no native architecture")
	}

	if _, ok := seen["noarch"]; !ok {
		architectures = append(architectures, "noarch")
		sort.Strings(architectures)
	}
	return ArchitectureSet{Primary: primary, Packages: architectures}, nil
}

func ResolveTargetInfo(osRelease []byte, releaseVersion string, architectures ArchitectureSet) (TargetInfo, error) {
	values, err := parseOSRelease(osRelease)
	if err != nil {
		return TargetInfo{}, err
	}
	if values["ID"] != "rhel" {
		return TargetInfo{}, fmt.Errorf("target operating system ID %q is not rhel", values["ID"])
	}
	versionID := values["VERSION_ID"]
	major, _, _ := strings.Cut(versionID, ".")
	if major == "" || !allASCIIDigits(major) {
		return TargetInfo{}, fmt.Errorf("invalid target RHEL VERSION_ID %q", versionID)
	}

	releaseVersion = strings.TrimSpace(releaseVersion)
	if releaseVersion == "" {
		releaseVersion = versionID
	}
	if releaseVersion == "" {
		return TargetInfo{}, fmt.Errorf("target release version is empty")
	}

	resolvedArchitectures, err := ResolveTargetArchitecture(architectures.Packages)
	if err != nil {
		return TargetInfo{}, err
	}
	if architectures.Primary != resolvedArchitectures.Primary {
		return TargetInfo{}, fmt.Errorf("target primary architecture %q does not match resolved architecture %q", architectures.Primary, resolvedArchitectures.Primary)
	}
	return TargetInfo{
		RHELVersion:    major,
		ReleaseVersion: releaseVersion,
		Architecture:   resolvedArchitectures.Primary,
		Architectures:  resolvedArchitectures.Packages,
	}, nil
}

func ResolveTargetReleaseVersion(root, versionID string) (string, error) {
	targetRoot, _, err := openTargetRoot(root)
	if err != nil {
		return "", err
	}
	defer targetRoot.Close()

	for _, path := range []string{"etc/dnf/vars/releasever", "etc/yum/vars/releasever"} {
		contents, err := targetRoot.ReadFile(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return "", fmt.Errorf("read target release version from %q: %w", path, err)
		}
		if value := strings.TrimSpace(string(contents)); value != "" {
			return value, nil
		}
	}

	if versionID = strings.TrimSpace(versionID); versionID != "" {
		return versionID, nil
	}
	return "", fmt.Errorf("target release version is unavailable")
}

func ResolveTargetRepoDirs(root string) ([]string, error) {
	targetRoot, rootPath, err := openTargetRoot(root)
	if err != nil {
		return nil, err
	}
	defer targetRoot.Close()

	contents, err := targetRoot.ReadFile("etc/dnf/dnf.conf")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read target DNF configuration: %w", err)
	}
	configured, err := parseDNFRepoDirs(contents)
	if err != nil {
		return nil, err
	}
	if len(configured) == 0 {
		return defaultTargetRepoDirs(targetRoot, rootPath)
	}

	repoDirs := make([]string, 0, len(configured))
	seen := make(map[string]struct{}, len(configured))
	for _, configuredDir := range configured {
		dir, relative, err := normalizeTargetRepoDir(rootPath, configuredDir)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[dir]; ok {
			continue
		}
		if _, err := targetRoot.Stat(relative); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("repository directory %q escapes target root: %w", configuredDir, err)
		}
		if err := validateTargetRepoFiles(targetRoot, relative); err != nil {
			return nil, fmt.Errorf("validate repository files in %q: %w", configuredDir, err)
		}
		seen[dir] = struct{}{}
		repoDirs = append(repoDirs, dir)
	}
	if len(repoDirs) == 0 {
		return defaultTargetRepoDirs(targetRoot, rootPath)
	}
	return repoDirs, nil
}

func defaultTargetRepoDirs(targetRoot *os.Root, rootPath string) ([]string, error) {
	const relative = "etc/yum.repos.d"
	if _, err := targetRoot.Stat(relative); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("validate default repository directory under target root: %w", err)
	}
	if err := validateTargetRepoFiles(targetRoot, relative); err != nil {
		return nil, fmt.Errorf("validate default repository files under target root: %w", err)
	}
	return []string{filepath.Join(rootPath, filepath.FromSlash(relative))}, nil
}

func validateTargetRepoFiles(targetRoot *os.Root, relativeDir string) error {
	dir, err := targetRoot.Open(relativeDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	entries, readErr := dir.ReadDir(-1)
	closeErr := dir.Close()
	if readErr != nil {
		return fmt.Errorf("read repository directory: %w", readErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close repository directory: %w", closeErr)
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".repo") {
			continue
		}
		if _, err := targetRoot.Stat(filepath.Join(relativeDir, entry.Name())); err != nil {
			return fmt.Errorf("resolve repository file %q within target root: %w", entry.Name(), err)
		}
	}
	return nil
}

func QueryInstalledRPMArchitectures(ctx context.Context, runner CommandRunner, rpmPath, installRoot string) ([]string, error) {
	if strings.TrimSpace(installRoot) == "" {
		return nil, fmt.Errorf("target install root is required")
	}
	if strings.TrimSpace(rpmPath) == "" {
		return nil, fmt.Errorf("rpm path is required")
	}
	databasePath, err := resolveTargetRPMDatabasePath(installRoot)
	if err != nil {
		return nil, err
	}
	if runner == nil {
		runner = execCommandRunner{}
	}

	output, err := runner.Run(ctx, rpmPath, "--root="+installRoot, "--dbpath="+databasePath, "--query", "--all", "--queryformat=%{ARCH}\\n")
	if err != nil {
		return nil, fmt.Errorf("query installed RPM architectures under %q: %w", installRoot, err)
	}

	seen := make(map[string]struct{})
	architectures := make([]string, 0)
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		architecture := strings.TrimSpace(scanner.Text())
		if architecture == "" || architecture == "src" || architecture == "nosrc" || architecture == "(none)" {
			continue
		}
		if _, ok := seen[architecture]; ok {
			continue
		}
		seen[architecture] = struct{}{}
		architectures = append(architectures, architecture)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read installed RPM architectures: %w", err)
	}
	sort.Strings(architectures)
	return architectures, nil
}

func resolveTargetRPMDatabasePath(root string) (string, error) {
	targetRoot, _, err := openTargetRoot(root)
	if err != nil {
		return "", err
	}
	defer targetRoot.Close()

	for _, databaseDir := range []string{"usr/lib/sysimage/rpm", "var/lib/rpm"} {
		for _, databaseFile := range []string{"Packages", "rpmdb.sqlite"} {
			path := filepath.Join(databaseDir, databaseFile)
			if _, err := targetRoot.Stat(path); err == nil {
				return string(filepath.Separator) + filepath.FromSlash(databaseDir), nil
			} else if !errors.Is(err, os.ErrNotExist) {
				return "", fmt.Errorf("inspect target RPM database at %q: %w", path, err)
			}
		}
	}
	return "", fmt.Errorf("target RPM database not found (checked /usr/lib/sysimage/rpm and /var/lib/rpm)")
}

func openTargetRoot(root string) (*os.Root, string, error) {
	if strings.TrimSpace(root) == "" {
		return nil, "", fmt.Errorf("target root is required")
	}
	rootPath, err := filepath.Abs(root)
	if err != nil {
		return nil, "", fmt.Errorf("resolve target root: %w", err)
	}
	rootPath = filepath.Clean(rootPath)
	targetRoot, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, "", fmt.Errorf("open target root %q: %w", rootPath, err)
	}
	return targetRoot, rootPath, nil
}

func parseOSRelease(contents []byte) (map[string]string, error) {
	values := make(map[string]string, 2)
	scanner := bufio.NewScanner(strings.NewReader(string(contents)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if key != "ID" && key != "VERSION_ID" {
			continue
		}
		value, err := parseOSReleaseValue(value)
		if err != nil {
			return nil, fmt.Errorf("parse target os-release %s: %w", key, err)
		}
		values[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read target os-release: %w", err)
	}
	return values, nil
}

func parseOSReleaseValue(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	quote := value[0]
	if quote == '"' || quote == '\'' {
		if len(value) < 2 || value[len(value)-1] != quote {
			return "", fmt.Errorf("unmatched quote")
		}
		return value[1 : len(value)-1], nil
	}
	if last := value[len(value)-1]; last == '"' || last == '\'' {
		return "", fmt.Errorf("unmatched quote")
	}
	return value, nil
}

func parseDNFRepoDirs(contents []byte) ([]string, error) {
	section := ""
	reposdir := ""
	scanner := bufio.NewScanner(strings.NewReader(string(contents)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		if !strings.EqualFold(section, "main") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(key), "reposdir") {
			continue
		}
		reposdir = strings.TrimSpace(value)
		if len(reposdir) >= 2 && (reposdir[0] == '"' || reposdir[0] == '\'') && reposdir[len(reposdir)-1] == reposdir[0] {
			reposdir = reposdir[1 : len(reposdir)-1]
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read target DNF configuration: %w", err)
	}
	if strings.TrimSpace(reposdir) == "" {
		return nil, nil
	}

	dirs := make([]string, 0)
	for _, dir := range strings.Split(reposdir, ",") {
		if dir = strings.TrimSpace(dir); dir != "" {
			dirs = append(dirs, dir)
		}
	}
	return dirs, nil
}

func normalizeTargetRepoDir(root, configured string) (string, string, error) {
	configured = strings.TrimSpace(configured)
	if configured == "" {
		return "", "", fmt.Errorf("target repository directory is empty")
	}
	if filepath.IsAbs(configured) {
		absolute := filepath.Clean(configured)
		if relative, err := filepath.Rel(root, absolute); err == nil && isWithinRoot(relative) {
			return absolute, relative, nil
		}
		configured = strings.TrimLeft(configured, string(filepath.Separator))
	}

	relative := filepath.Clean(configured)
	if !isWithinRoot(relative) {
		return "", "", fmt.Errorf("repository directory %q escapes target root", configured)
	}
	dir := filepath.Clean(filepath.Join(root, relative))
	resolvedRelative, err := filepath.Rel(root, dir)
	if err != nil || !isWithinRoot(resolvedRelative) {
		return "", "", fmt.Errorf("repository directory %q escapes target root", configured)
	}
	return dir, resolvedRelative, nil
}

func isWithinRoot(relative string) bool {
	return relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

func allASCIIDigits(value string) bool {
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return value != ""
}
