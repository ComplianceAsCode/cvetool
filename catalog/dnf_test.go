package catalog

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"
)

type fakeCommandRunner struct {
	args   [][]string
	output []byte
	err    error
}

func (f *fakeCommandRunner) Run(_ context.Context, path string, args ...string) ([]byte, error) {
	f.args = append(f.args, append([]string{path}, args...))
	return f.output, f.err
}

func TestDNFUsesExactRepositoryAndQueryFormat(t *testing.T) {
	runner := &fakeCommandRunner{output: []byte("bash\t0\t5.1.8\t6.el9\tx86_64\nexample\t0\t1.0\t1.el9\tnoarch\n")}
	got, err := QueryDNFWithOptions(context.Background(), runner, DNFOptions{
		Path: "dnf", Architecture: "x86_64", legacyHostQuery: true,
	}, "rhel-9-for-x86_64-baseos-rpms")
	if err != nil {
		t.Fatal(err)
	}
	want := []NEVRA{
		{Name: "bash", Epoch: "0", Version: "5.1.8", Release: "6.el9", Arch: "x86_64"},
		{Name: "example", Epoch: "0", Version: "1.0", Release: "1.el9", Arch: "noarch"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rows mismatch: %#v != %#v", got, want)
	}
	wantArgs := [][]string{{"dnf", "--quiet", "--repo=rhel-9-for-x86_64-baseos-rpms", "--arch=x86_64,noarch", "repoquery", "--qf", dnfQueryFormat}}
	if !reflect.DeepEqual(runner.args, wantArgs) {
		t.Fatalf("unexpected command: %#v != %#v", runner.args, wantArgs)
	}
}

func TestDNFIgnoresSubscriptionManagerStatusOutput(t *testing.T) {
	runner := noisyCommandRunner{}
	got, err := QueryDNFWithOptions(context.Background(), runner, DNFOptions{
		Path: "dnf", Architecture: "x86_64", legacyHostQuery: true,
	}, "repo")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "bash" {
		t.Fatalf("unexpected packages: %#v", got)
	}
}

type noisyCommandRunner struct{}

func (noisyCommandRunner) Run(_ context.Context, _ string, args ...string) ([]byte, error) {
	for _, arg := range args {
		if arg == "--quiet" {
			return []byte("bash\t0\t5.1.8\t6.el9\tx86_64\n"), nil
		}
	}
	return []byte("Updating Subscription Management repositories.\nbash\t0\t5.1.8\t6.el9\tx86_64\n"), nil
}

func TestDNFRejectsMalformedRowsAndCommandErrors(t *testing.T) {
	for _, test := range []struct {
		name   string
		output []byte
		err    error
	}{
		{name: "malformed", output: []byte("bad\trow\n")},
		{name: "command", err: errors.New("failed")},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := QueryDNFWithOptions(context.Background(), &fakeCommandRunner{output: test.output, err: test.err}, DNFOptions{
				Path: "dnf", Architecture: "x86_64", legacyHostQuery: true,
			}, "repo")
			if err == nil {
				t.Fatal("QueryDNF succeeded")
			}
		})
	}
}

func TestDNFDeduplicatesRowsAndRetainsMultiplePackages(t *testing.T) {
	runner := &fakeCommandRunner{output: []byte("bash\t0\t5.1.8\t6.el9\tx86_64\nbash\t0\t5.1.8\t6.el9\tx86_64\nvim\t0\t9.0\t1.el9\tx86_64\n")}
	got, err := QueryDNFWithOptions(context.Background(), runner, DNFOptions{
		Path: "dnf", Architecture: "x86_64", legacyHostQuery: true,
	}, "repo")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected two unique packages, got %#v", got)
	}
}

func TestQueryDNFUsesTargetInstallrootAndArchitectures(t *testing.T) {
	scratchDir := privateDNFTestScratchDir(t)
	runner := &fakeCommandRunner{output: []byte("bash\t0\t5.1\t1.el10\tx86_64\n")}
	options := testTargetDNFOptions(scratchDir)
	options.RepoDirs = []string{"/target/etc/yum.repos.d", "/target/etc/dnf/repos.d"}

	got, err := QueryDNFWithOptions(context.Background(), runner, options, "ubi-10-for-x86_64-baseos-rpms")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "bash" {
		t.Fatalf("unexpected packages: %#v", got)
	}

	wantArgs := []string{
		"dnf",
		"--quiet",
		"--disableplugin=subscription-manager,product-id",
		"--installroot=/target",
		"--setopt=reposdir=/target/etc/yum.repos.d,/target/etc/dnf/repos.d",
		"--releasever=10.2",
		"--forcearch=x86_64",
		"--setopt=cachedir=" + scratchDir + "/cache",
		"--setopt=persistdir=" + scratchDir + "/state",
		"--setopt=logdir=" + scratchDir + "/log",
		"--repo=ubi-10-for-x86_64-baseos-rpms",
		"repoquery",
		"--arch=x86_64,i686,noarch",
		"--qf",
		dnfQueryFormat,
	}
	if !reflect.DeepEqual(runner.args, [][]string{wantArgs}) {
		t.Fatalf("unexpected target query command:\n got: %#v\nwant: %#v", runner.args, [][]string{wantArgs})
	}
}

func TestEnabledRepositoriesParsesDNF4AndDNF5(t *testing.T) {
	for _, test := range []struct {
		name   string
		output string
		want   []string
	}{
		{
			name: "dnf4",
			output: "repo id                              repo name                         status\n" +
				"ubi-10-for-x86_64-baseos-rpms        Red Hat UBI 10 BaseOS            42\n" +
				"ubi-10-for-x86_64-appstream-rpms     Red Hat UBI 10 AppStream         314\n" +
				"repolist: 1,234\n",
			want: []string{"ubi-10-for-x86_64-baseos-rpms", "ubi-10-for-x86_64-appstream-rpms"},
		},
		{
			name: "dnf5",
			output: "repo id                                  repo name\n" +
				"rhel-10-for-x86_64-baseos-rpms           Red Hat Enterprise Linux 10 BaseOS (RPMs)\n" +
				"repolist: 1\n",
			want: []string{"rhel-10-for-x86_64-baseos-rpms"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := &fakeCommandRunner{output: []byte(test.output)}
			options := testTargetDNFOptions(privateDNFTestScratchDir(t))

			got, err := EnabledRepositories(context.Background(), runner, options)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("repository IDs mismatch: %#v != %#v", got, test.want)
			}
			if !slices.Contains(runner.args[0], "repolist") || !slices.Contains(runner.args[0], "--enabled") {
				t.Fatalf("enabled repository command missing: %#v", runner.args[0])
			}
			if !slices.Contains(runner.args[0], "--setopt=reposdir=/target/etc/yum.repos.d") {
				t.Fatalf("target repository directory missing: %#v", runner.args[0])
			}
			if strings.Contains(strings.Join(runner.args[0], " "), "reposdir=/etc/yum.repos.d") {
				t.Fatalf("scanner-host repository directory was used: %#v", runner.args[0])
			}
		})
	}
}

func TestEnabledRepositoriesDoesNotPassArchitectureToRepolist(t *testing.T) {
	runner := &fakeCommandRunner{output: []byte("repo id repo name\nrepo-a Repository A\n")}
	_, err := EnabledRepositories(context.Background(), runner, testTargetDNFOptions(privateDNFTestScratchDir(t)))
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.args) != 1 {
		t.Fatalf("expected one DNF invocation, got %#v", runner.args)
	}
	args := runner.args[0][1:]
	if !slices.Contains(args, "repolist") || !slices.Contains(args, "--enabled") {
		t.Fatalf("expected enabled-repository listing, got %#v", args)
	}
	for _, arg := range args {
		if arg == "--arch" || strings.HasPrefix(arg, "--arch=") {
			t.Fatalf("repolist received repoquery-only architecture option %q: %#v", arg, args)
		}
	}
}

func TestEnabledRepositoriesRejectsMalformedOutput(t *testing.T) {
	runner := &fakeCommandRunner{output: []byte("not a DNF repository table\n")}
	_, err := EnabledRepositories(context.Background(), runner, testTargetDNFOptions(privateDNFTestScratchDir(t)))
	if err == nil {
		t.Fatal("EnabledRepositories accepted malformed output")
	}
}

func TestEnabledRepositoriesIgnoresRepolistCount(t *testing.T) {
	runner := &fakeCommandRunner{output: []byte("repo id repo name\nrepo-a Repository A\nrepolist: garbage\n")}
	got, err := EnabledRepositories(context.Background(), runner, testTargetDNFOptions(privateDNFTestScratchDir(t)))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []string{"repo-a"}) {
		t.Fatalf("unexpected repositories: %#v", got)
	}
}

func TestEnabledRepositoriesReturnsCommandErrors(t *testing.T) {
	runner := &fakeCommandRunner{err: errors.New("failed")}
	_, err := EnabledRepositories(context.Background(), runner, testTargetDNFOptions(privateDNFTestScratchDir(t)))
	if err == nil {
		t.Fatal("EnabledRepositories succeeded after a command error")
	}
}

func TestEnabledRepositoriesDoesNotFallBackToHostRepositories(t *testing.T) {
	for _, repoDirs := range [][]string{nil, {"/etc/yum.repos.d"}} {
		runner := &fakeCommandRunner{output: []byte("repo id repo name\nhost-repository Host repository\n")}
		options := testTargetDNFOptions(privateDNFTestScratchDir(t))
		options.RepoDirs = repoDirs

		_, err := EnabledRepositories(context.Background(), runner, options)
		if err == nil {
			t.Fatalf("EnabledRepositories accepted repo dirs %#v", repoDirs)
		}
		if len(runner.args) != 0 {
			t.Fatalf("DNF ran without target-only repository dirs: %#v", runner.args)
		}
	}
}

func TestExecCommandRunnerSetsCLocale(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh is unavailable")
	}
	t.Setenv("LC_ALL", "test_LOCALE")

	output, err := (execCommandRunner{}).Run(context.Background(), sh, "-c", "printf '%s' \"$LC_ALL\"")
	if err != nil {
		t.Fatal(err)
	}
	if got := string(output); got != "C" {
		t.Fatalf("LC_ALL = %q, want C", got)
	}
}

func TestQueryDNFWithOptionsRejectsScratchSymlinkIntoTargetRoot(t *testing.T) {
	targetRoot := t.TempDir()
	if err := os.Mkdir(filepath.Join(targetRoot, "scratch"), 0o700); err != nil {
		t.Fatal(err)
	}
	scratchLink := filepath.Join(t.TempDir(), "scratch-link")
	if err := os.Symlink(filepath.Join(targetRoot, "scratch"), scratchLink); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	runner := &fakeCommandRunner{output: []byte("bash\t0\t5.1\t1.el10\tx86_64\n")}
	options := testTargetDNFOptions(privateDNFTestScratchDir(t))
	options.InstallRoot = targetRoot
	options.RepoDirs = []string{filepath.Join(targetRoot, "etc", "yum.repos.d")}
	options.ScratchDir = scratchLink

	_, err := QueryDNFWithOptions(context.Background(), runner, options, "target-repo")
	if err == nil {
		t.Fatal("QueryDNFWithOptions accepted scratch path resolving into target root")
	}
	if len(runner.args) != 0 {
		t.Fatalf("DNF ran with target-root scratch path: %#v", runner.args)
	}
}

func TestQueryDNFWithOptionsRejectsScratchChildSymlinksIntoTargetRoot(t *testing.T) {
	for _, child := range []string{"cache", "state", "log"} {
		t.Run(child, func(t *testing.T) {
			targetRoot := t.TempDir()
			targetWriteDir := filepath.Join(targetRoot, child)
			if err := os.Mkdir(targetWriteDir, 0o700); err != nil {
				t.Fatal(err)
			}
			scratchDir := privateDNFTestScratchDir(t)
			if err := os.Symlink(targetWriteDir, filepath.Join(scratchDir, child)); err != nil {
				t.Skipf("symlink unavailable: %v", err)
			}
			runner := &fakeCommandRunner{output: []byte("bash\t0\t5.1\t1.el10\tx86_64\n")}
			options := testTargetDNFOptions(scratchDir)
			options.InstallRoot = targetRoot
			options.RepoDirs = []string{filepath.Join(targetRoot, "etc", "yum.repos.d")}

			_, err := QueryDNFWithOptions(context.Background(), runner, options, "target-repo")
			if err == nil {
				t.Fatalf("QueryDNFWithOptions accepted %s symlink into target root", child)
			}
			if len(runner.args) != 0 {
				t.Fatalf("DNF ran with %s symlink into target root: %#v", child, runner.args)
			}
		})
	}
}

func TestQueryDNFWithOptionsRejectsDanglingScratchSymlinksIntoTargetRoot(t *testing.T) {
	t.Run("scratch root", func(t *testing.T) {
		targetRoot := t.TempDir()
		scratchLink := filepath.Join(t.TempDir(), "scratch-link")
		if err := os.Symlink(filepath.Join(targetRoot, "future-scratch"), scratchLink); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		runner := &fakeCommandRunner{output: []byte("bash\t0\t5.1\t1.el10\tx86_64\n")}
		options := testTargetDNFOptions(privateDNFTestScratchDir(t))
		options.InstallRoot = targetRoot
		options.RepoDirs = []string{filepath.Join(targetRoot, "etc", "yum.repos.d")}
		options.ScratchDir = scratchLink

		_, err := QueryDNFWithOptions(context.Background(), runner, options, "target-repo")
		if err == nil {
			t.Fatal("QueryDNFWithOptions accepted dangling scratch symlink into target root")
		}
		if len(runner.args) != 0 {
			t.Fatalf("DNF ran with dangling scratch symlink into target root: %#v", runner.args)
		}
	})

	t.Run("cache child", func(t *testing.T) {
		targetRoot := t.TempDir()
		scratchDir := privateDNFTestScratchDir(t)
		if err := os.Symlink(filepath.Join(targetRoot, "future-cache"), filepath.Join(scratchDir, "cache")); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		runner := &fakeCommandRunner{output: []byte("bash\t0\t5.1\t1.el10\tx86_64\n")}
		options := testTargetDNFOptions(scratchDir)
		options.InstallRoot = targetRoot
		options.RepoDirs = []string{filepath.Join(targetRoot, "etc", "yum.repos.d")}

		_, err := QueryDNFWithOptions(context.Background(), runner, options, "target-repo")
		if err == nil {
			t.Fatal("QueryDNFWithOptions accepted dangling cache symlink into target root")
		}
		if len(runner.args) != 0 {
			t.Fatalf("DNF ran with dangling cache symlink into target root: %#v", runner.args)
		}
	})
}

func TestEnabledRepositoriesRejectsRepoDirSymlinkOutsideTargetRoot(t *testing.T) {
	targetRoot := t.TempDir()
	outsideRepoDir := t.TempDir()
	repoDir := filepath.Join(targetRoot, "etc", "yum.repos.d")
	if err := os.MkdirAll(filepath.Dir(repoDir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideRepoDir, repoDir); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	runner := &fakeCommandRunner{output: []byte("repo id repo name\n")}
	options := testTargetDNFOptions(privateDNFTestScratchDir(t))
	options.InstallRoot = targetRoot
	options.RepoDirs = []string{repoDir}

	_, err := EnabledRepositories(context.Background(), runner, options)
	if err == nil {
		t.Fatal("EnabledRepositories accepted a repository directory resolving outside target root")
	}
	if len(runner.args) != 0 {
		t.Fatalf("DNF ran with a repository directory outside target root: %#v", runner.args)
	}
}

func TestEnabledRepositoriesRejectsRepoDirsWithDNFListDelimiters(t *testing.T) {
	for _, test := range []struct {
		name    string
		repoDir string
	}{
		{name: "comma", repoDir: "/target/etc/yum.repos.d,/etc/yum.repos.d"},
		{name: "space", repoDir: "/target/etc/yum.repos.d /etc/yum.repos.d"},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := &fakeCommandRunner{output: []byte("repo id repo name\ntarget-repo Target repository\n")}
			options := testTargetDNFOptions(privateDNFTestScratchDir(t))
			options.RepoDirs = []string{test.repoDir}

			_, err := EnabledRepositories(context.Background(), runner, options)
			if err == nil {
				t.Fatalf("EnabledRepositories accepted reposdir with %q delimiter", test.name)
			}
			if len(runner.args) != 0 {
				t.Fatalf("DNF ran with delimiter-injected reposdir: %#v", runner.args)
			}
		})
	}
}

func TestEnabledRepositoriesRejectsBoundaryWhitespaceInRepoDirs(t *testing.T) {
	for _, test := range []struct {
		name    string
		repoDir string
	}{
		{name: "leading space", repoDir: " /target/etc/yum.repos.d"},
		{name: "trailing tab", repoDir: "/target/etc/yum.repos.d\t"},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := &fakeCommandRunner{output: []byte("repo id repo name\ntarget-repo Target repository\n")}
			options := testTargetDNFOptions(privateDNFTestScratchDir(t))
			options.RepoDirs = []string{test.repoDir}

			_, err := EnabledRepositories(context.Background(), runner, options)
			if err == nil {
				t.Fatal("EnabledRepositories accepted repository directory with boundary whitespace")
			}
			if len(runner.args) != 0 {
				t.Fatalf("DNF ran with repository directory containing boundary whitespace: %#v", runner.args)
			}
		})
	}
}

func TestQueryDNFWithOptionsAllowsPrivateTempScratchForHostRoot(t *testing.T) {
	scratchDir := t.TempDir()
	if err := os.Chmod(scratchDir, 0o700); err != nil {
		t.Fatal(err)
	}
	tempDir, err := filepath.Abs(os.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	relative, err := filepath.Rel(tempDir, scratchDir)
	if err != nil {
		t.Fatal(err)
	}
	if relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		t.Fatalf("test scratch directory %q is not beneath os.TempDir() %q", scratchDir, tempDir)
	}
	info, err := os.Stat(scratchDir)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("t.TempDir() mode = %04o, want owner-only directory mode 0700", info.Mode().Perm())
	}

	runner := &fakeCommandRunner{output: []byte("bash\t0\t5.1\t1.el10\tx86_64\n")}
	options := testTargetDNFOptions(scratchDir)
	options.InstallRoot = "/"
	options.RepoDirs = []string{"/etc/yum.repos.d"}

	_, err = QueryDNFWithOptions(context.Background(), runner, options, "host-root-repo")
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.args) != 1 {
		t.Fatalf("expected one DNF invocation, got %#v", runner.args)
	}
	for _, arg := range []string{
		"--installroot=/",
		"--setopt=cachedir=" + filepath.Join(scratchDir, "cache"),
		"--setopt=persistdir=" + filepath.Join(scratchDir, "state"),
		"--setopt=logdir=" + filepath.Join(scratchDir, "log"),
	} {
		if !slices.Contains(runner.args[0], arg) {
			t.Fatalf("DNF command missing %q: %#v", arg, runner.args[0])
		}
	}
}

func TestQueryDNFWithOptionsRejectsTempRootForHostRoot(t *testing.T) {
	assertHostRootScratchRejected(t, filepath.Clean(os.TempDir()))
}

func TestQueryDNFWithOptionsRejectsScratchOutsideTempForHostRoot(t *testing.T) {
	scratchDir, err := os.MkdirTemp(".", ".cvetool-outside-temp-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(scratchDir) })
	scratchDir, err = filepath.Abs(scratchDir)
	if err != nil {
		t.Fatal(err)
	}
	tempDir, err := filepath.Abs(os.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	relative, err := filepath.Rel(tempDir, scratchDir)
	if err != nil {
		t.Fatal(err)
	}
	if relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))) {
		t.Skipf("working directory %q is beneath os.TempDir() %q", scratchDir, tempDir)
	}
	assertHostRootScratchRejected(t, scratchDir)
}

func TestQueryDNFWithOptionsRejectsPermissiveScratchForHostRoot(t *testing.T) {
	scratchDir, err := os.MkdirTemp(os.TempDir(), ".cvetool-permissive-scratch-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(scratchDir) })
	if err := os.Chmod(scratchDir, 0o755); err != nil {
		t.Fatal(err)
	}
	assertHostRootScratchRejected(t, scratchDir)
}

func TestQueryDNFWithOptionsRejectsPermissiveScratchForMountedRoot(t *testing.T) {
	targetRoot := t.TempDir()
	scratchDir := t.TempDir()
	if err := os.Chmod(scratchDir, 0o755); err != nil {
		t.Fatal(err)
	}
	runner := &fakeCommandRunner{output: []byte("bash\t0\t5.1\t1.el10\tx86_64\n")}
	options := testTargetDNFOptions(scratchDir)
	options.InstallRoot = targetRoot
	options.RepoDirs = []string{filepath.Join(targetRoot, "etc", "yum.repos.d")}

	_, err := QueryDNFWithOptions(context.Background(), runner, options, "target-repo")
	if err == nil {
		t.Fatal("QueryDNFWithOptions accepted non-private mounted-root scratch directory")
	}
	if len(runner.args) != 0 {
		t.Fatalf("DNF ran with non-private mounted-root scratch directory: %#v", runner.args)
	}
}

func TestQueryDNFWithOptionsRejectsForeignOwnedScratchForMountedRoot(t *testing.T) {
	scratchDir := privateDNFTestScratchDir(t)
	foreignUID := os.Geteuid() + 1
	if os.Geteuid() != 0 {
		foreignUID = 0
	}
	if err := os.Chown(scratchDir, foreignUID, -1); err != nil {
		t.Skipf("cannot create foreign-owned scratch fixture: %v", err)
	}
	info, err := os.Stat(scratchDir)
	if err != nil {
		t.Fatal(err)
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("scratch ownership metadata is unavailable")
	}
	if int(owner.Uid) == os.Geteuid() {
		t.Fatalf("foreign scratch fixture is still owned by effective user %d", os.Geteuid())
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("foreign scratch mode = %04o, want 0700", info.Mode().Perm())
	}

	targetRoot := t.TempDir()
	runner := &fakeCommandRunner{output: []byte("bash\t0\t5.1\t1.el10\tx86_64\n")}
	options := testTargetDNFOptions(scratchDir)
	options.InstallRoot = targetRoot
	options.RepoDirs = []string{filepath.Join(targetRoot, "etc", "yum.repos.d")}

	_, err = QueryDNFWithOptions(context.Background(), runner, options, "target-repo")
	if err == nil {
		t.Fatal("QueryDNFWithOptions accepted foreign-owned mounted-root scratch directory")
	}
	if len(runner.args) != 0 {
		t.Fatalf("DNF ran with foreign-owned mounted-root scratch directory: %#v", runner.args)
	}
}

func TestValidateDNFScratchInfoRejectsForeignOwner(t *testing.T) {
	info, err := os.Stat(privateDNFTestScratchDir(t))
	if err != nil {
		t.Fatal(err)
	}
	foreignUID := uint32(0)
	if os.Geteuid() == 0 {
		foreignUID = 1
	}
	infoWithForeignOwner := dnfScratchInfoWithSystem{FileInfo: info, system: &syscall.Stat_t{Uid: foreignUID}}

	err = validateDNFScratchInfo(infoWithForeignOwner)
	if err == nil || !strings.Contains(err.Error(), "owned by effective user") {
		t.Fatalf("validateDNFScratchInfo error = %v, want foreign-owner rejection", err)
	}
}

func TestQueryDNFWithOptionsRejectsForeignOwnedScratchForHostRoot(t *testing.T) {
	scratchDir, err := os.MkdirTemp(t.TempDir(), ".cvetool-foreign-owner-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(scratchDir) })
	if err := os.Chmod(scratchDir, 0o700); err != nil {
		t.Fatal(err)
	}

	foreignUID := os.Geteuid() + 1
	if os.Geteuid() != 0 {
		foreignUID = 0
	}
	if err := os.Chown(scratchDir, foreignUID, -1); err != nil {
		t.Skipf("cannot chown scratch fixture to another user: %v", err)
	}
	info, err := os.Stat(scratchDir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("foreign scratch mode = %04o, want 0700", info.Mode().Perm())
	}

	assertHostRootScratchRejected(t, scratchDir)
}

func assertHostRootScratchRejected(t *testing.T, scratchDir string) {
	t.Helper()
	runner := &fakeCommandRunner{output: []byte("bash\t0\t5.1\t1.el10\tx86_64\n")}
	options := testTargetDNFOptions(scratchDir)
	options.InstallRoot = "/"
	options.RepoDirs = []string{"/etc/yum.repos.d"}

	_, err := QueryDNFWithOptions(context.Background(), runner, options, "host-root-repo")
	if err == nil {
		t.Fatal("QueryDNFWithOptions accepted unsafe host-root scratch directory")
	}
	if len(runner.args) != 0 {
		t.Fatalf("DNF ran with unsafe host-root scratch directory: %#v", runner.args)
	}
}

func testTargetDNFOptions(scratchDir string) DNFOptions {
	return DNFOptions{
		Path:           "dnf",
		InstallRoot:    "/target",
		ScratchDir:     scratchDir,
		ReleaseVersion: "10.2",
		Architecture:   "x86_64",
		RepoDirs:       []string{"/target/etc/yum.repos.d"},
		Architectures:  []string{"x86_64", "i686"},
	}
}

func privateDNFTestScratchDir(t *testing.T) string {
	t.Helper()
	scratchDir := t.TempDir()
	if err := os.Chmod(scratchDir, 0o700); err != nil {
		t.Fatal(err)
	}
	return scratchDir
}

type dnfScratchInfoWithSystem struct {
	os.FileInfo
	system any
}

func (info dnfScratchInfoWithSystem) Sys() any {
	return info.system
}
