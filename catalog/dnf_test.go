package catalog

import (
	"context"
	"errors"
	"reflect"
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
	got, err := QueryDNF(context.Background(), runner, "dnf", "rhel-9-for-x86_64-baseos-rpms", "x86_64")
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
	got, err := QueryDNF(context.Background(), runner, "dnf", "repo", "x86_64")
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
			_, err := QueryDNF(context.Background(), &fakeCommandRunner{output: test.output, err: test.err}, "dnf", "repo", "x86_64")
			if err == nil {
				t.Fatal("QueryDNF succeeded")
			}
		})
	}
}

func TestDNFDeduplicatesRowsAndRetainsMultiplePackages(t *testing.T) {
	runner := &fakeCommandRunner{output: []byte("bash\t0\t5.1.8\t6.el9\tx86_64\nbash\t0\t5.1.8\t6.el9\tx86_64\nvim\t0\t9.0\t1.el9\tx86_64\n")}
	got, err := QueryDNF(context.Background(), runner, "dnf", "repo", "x86_64")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected two unique packages, got %#v", got)
	}
}
