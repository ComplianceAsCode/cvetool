package catalog

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

type CommandRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type DNFOptions struct {
	Path            string
	InstallRoot     string
	ScratchDir      string
	ReleaseVersion  string
	Architecture    string
	RepoDirs        []string
	Architectures   []string
	legacyHostQuery bool
}

type execCommandRunner struct{}

func (execCommandRunner) Run(ctx context.Context, path string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	return cmd.Output()
}

const dnfQueryFormat = "%{name}\\t%{epoch}\\t%{version}\\t%{release}\\t%{arch}"

func QueryDNFWithOptions(ctx context.Context, runner CommandRunner, options DNFOptions, repositoryID string) ([]NEVRA, error) {
	var args []string
	if options.legacyHostQuery {
		args = []string{"--quiet", "--repo=" + repositoryID, "--arch=" + options.Architecture + ",noarch"}
		args = append(args, "repoquery", "--qf", dnfQueryFormat)
	} else {
		if strings.TrimSpace(repositoryID) == "" {
			return nil, fmt.Errorf("repository ID is required")
		}
		var err error
		args, err = targetDNFArgs(options)
		if err != nil {
			return nil, err
		}
		args = append(args, "--repo="+repositoryID)

		architectures := make([]string, 0, len(options.Architectures)+1)
		seenArchitectures := make(map[string]struct{}, len(options.Architectures)+1)
		for _, packageArchitecture := range options.Architectures {
			packageArchitecture = strings.TrimSpace(packageArchitecture)
			if packageArchitecture == "" {
				continue
			}
			if _, ok := seenArchitectures[packageArchitecture]; ok {
				continue
			}
			seenArchitectures[packageArchitecture] = struct{}{}
			architectures = append(architectures, packageArchitecture)
		}
		if len(architectures) == 0 {
			return nil, fmt.Errorf("target package architectures are required")
		}
		if _, ok := seenArchitectures["noarch"]; !ok {
			architectures = append(architectures, "noarch")
		}
		args = append(args, "repoquery", "--arch="+strings.Join(architectures, ","), "--qf", dnfQueryFormat)
	}
	return queryDNF(ctx, runner, options.Path, repositoryID, args...)
}

func EnabledRepositories(ctx context.Context, runner CommandRunner, options DNFOptions) ([]string, error) {
	args, err := targetDNFArgs(options)
	if err != nil {
		return nil, err
	}
	args = append(args, "repolist", "--enabled")
	output, err := runDNF(ctx, runner, options.Path, args...)
	if err != nil {
		return nil, fmt.Errorf("list enabled target repositories: %w", err)
	}
	repositories, err := parseEnabledRepositories(output)
	if err != nil {
		return nil, fmt.Errorf("parse enabled target repositories: %w", err)
	}
	return repositories, nil
}

func targetDNFArgs(options DNFOptions) ([]string, error) {
	path := strings.TrimSpace(options.Path)
	if path == "" {
		return nil, fmt.Errorf("DNF path is required")
	}
	installRoot := filepath.Clean(strings.TrimSpace(options.InstallRoot))
	if installRoot == "." || !filepath.IsAbs(installRoot) {
		return nil, fmt.Errorf("absolute target install root is required")
	}
	scratchDir := filepath.Clean(strings.TrimSpace(options.ScratchDir))
	if scratchDir == "." || !filepath.IsAbs(scratchDir) {
		return nil, fmt.Errorf("absolute DNF scratch directory is required")
	}
	resolvedInstallRoot, err := resolveDNFPath(installRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve target install root: %w", err)
	}
	resolvedScratchDir, err := resolveDNFPath(scratchDir)
	if err != nil {
		return nil, fmt.Errorf("resolve DNF scratch directory: %w", err)
	}
	if err := validateDNFScratch(installRoot, scratchDir, resolvedInstallRoot, resolvedScratchDir); err != nil {
		return nil, err
	}
	for _, child := range []string{"cache", "state", "log"} {
		writePath := filepath.Join(scratchDir, child)
		resolvedWritePath, err := resolveDNFPath(writePath)
		if err != nil {
			return nil, fmt.Errorf("resolve DNF %s directory: %w", child, err)
		}
		if !dnfPathWithin(resolvedScratchDir, resolvedWritePath) {
			return nil, fmt.Errorf("DNF %s directory resolves outside scratch directory", child)
		}
	}
	releaseVersion := strings.TrimSpace(options.ReleaseVersion)
	if releaseVersion == "" {
		return nil, fmt.Errorf("target release version is required")
	}
	architecture := strings.TrimSpace(options.Architecture)
	if architecture == "" {
		return nil, fmt.Errorf("target architecture is required")
	}
	if len(options.RepoDirs) == 0 {
		return nil, fmt.Errorf("target repository directories are required")
	}
	repoDirs := make([]string, 0, len(options.RepoDirs))
	seenRepoDirs := make(map[string]struct{}, len(options.RepoDirs))
	for _, repoDir := range options.RepoDirs {
		if strings.ContainsAny(repoDir, ", \t\r\n\v\f") {
			return nil, fmt.Errorf("repository directory %q contains a DNF list delimiter", repoDir)
		}
		repoDir = filepath.Clean(repoDir)
		if repoDir == "." || !filepath.IsAbs(repoDir) || !dnfPathWithin(installRoot, repoDir) {
			return nil, fmt.Errorf("repository directory %q is not under target install root %q", repoDir, installRoot)
		}
		resolvedRepoDir, err := resolveDNFPath(repoDir)
		if err != nil {
			return nil, fmt.Errorf("resolve target repository directory %q: %w", repoDir, err)
		}
		if !dnfPathWithin(resolvedInstallRoot, resolvedRepoDir) {
			return nil, fmt.Errorf("repository directory %q resolves outside target install root %q", repoDir, installRoot)
		}
		if _, ok := seenRepoDirs[repoDir]; ok {
			continue
		}
		seenRepoDirs[repoDir] = struct{}{}
		repoDirs = append(repoDirs, repoDir)
	}
	if len(repoDirs) == 0 {
		return nil, fmt.Errorf("target repository directories are required")
	}

	return []string{
		"--quiet",
		"--disableplugin=subscription-manager,product-id",
		"--installroot=" + installRoot,
		"--setopt=reposdir=" + strings.Join(repoDirs, ","),
		"--releasever=" + releaseVersion,
		"--forcearch=" + architecture,
		"--setopt=cachedir=" + filepath.Join(scratchDir, "cache"),
		"--setopt=persistdir=" + filepath.Join(scratchDir, "state"),
		"--setopt=logdir=" + filepath.Join(scratchDir, "log"),
	}, nil
}

func validateDNFScratch(installRoot, scratchDir, resolvedInstallRoot, resolvedScratchDir string) error {
	if installRoot != string(filepath.Separator) {
		if dnfPathWithin(resolvedInstallRoot, resolvedScratchDir) {
			return fmt.Errorf("DNF scratch directory must be outside target install root")
		}
	} else {
		tempDir, err := filepath.Abs(os.TempDir())
		if err != nil {
			return fmt.Errorf("resolve host temp directory: %w", err)
		}
		tempDir = filepath.Clean(tempDir)
		resolvedTempDir, err := resolveDNFPath(tempDir)
		if err != nil {
			return fmt.Errorf("resolve host temp directory: %w", err)
		}
		if scratchDir == tempDir || !dnfPathWithin(tempDir, scratchDir) || resolvedScratchDir == resolvedTempDir || !dnfPathWithin(resolvedTempDir, resolvedScratchDir) {
			return fmt.Errorf("host-root DNF scratch directory must be a dedicated directory under %q", tempDir)
		}
	}

	info, err := os.Stat(resolvedScratchDir)
	if err != nil {
		return fmt.Errorf("stat DNF scratch directory: %w", err)
	}
	return validateDNFScratchInfo(info)
}

func validateDNFScratchInfo(info os.FileInfo) error {
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		return fmt.Errorf("DNF scratch directory must be owner-only with mode 0700")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(owner.Uid) != os.Geteuid() {
		return fmt.Errorf("DNF scratch directory must be owned by effective user %d", os.Geteuid())
	}
	return nil
}

func dnfPathWithin(root, path string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && (relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))))
}

func resolveDNFPath(path string) (string, error) {
	current := filepath.Clean(path)
	var suffix []string
	for {
		resolved, err := filepath.EvalSymlinks(current)
		if err == nil {
			for i := len(suffix) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, suffix[i])
			}
			return filepath.Clean(resolved), nil
		}
		info, lstatErr := os.Lstat(current)
		if lstatErr == nil && info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("path %q contains a dangling symlink: %w", current, err)
		}
		if lstatErr != nil && !os.IsNotExist(lstatErr) {
			return "", lstatErr
		}
		if !os.IsNotExist(err) {
			return "", err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", err
		}
		suffix = append(suffix, filepath.Base(current))
		current = parent
	}
}

func parseEnabledRepositories(output []byte) ([]string, error) {
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	repositories := make([]string, 0)
	seen := make(map[string]struct{})
	headerSeen := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.EqualFold(fields[0], "repo") && strings.EqualFold(fields[1], "id") {
			headerSeen = true
			continue
		}
		if !headerSeen {
			return nil, fmt.Errorf("invalid DNF repolist output before repository header: %q", line)
		}
		if strings.HasPrefix(strings.ToLower(line), "repolist:") {
			continue
		}
		if len(fields) < 2 {
			return nil, fmt.Errorf("invalid DNF repository row %q", line)
		}
		if _, ok := seen[fields[0]]; ok {
			continue
		}
		seen[fields[0]] = struct{}{}
		repositories = append(repositories, fields[0])
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read DNF repolist output: %w", err)
	}
	if !headerSeen {
		return nil, fmt.Errorf("invalid DNF repolist output: repository header missing")
	}
	return repositories, nil
}

func queryDNF(ctx context.Context, runner CommandRunner, dnfPath, repositoryID string, args ...string) ([]NEVRA, error) {
	output, err := runDNF(ctx, runner, dnfPath, args...)
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

func runDNF(ctx context.Context, runner CommandRunner, path string, args ...string) ([]byte, error) {
	if runner == nil {
		runner = execCommandRunner{}
	}
	return runner.Run(ctx, path, args...)
}
