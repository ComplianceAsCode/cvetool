package catalog

import (
	"testing"

	claircore "github.com/quay/claircore"
)

func TestNEVRAEquivalentRepresentationsHaveSameKey(t *testing.T) {
	clairPackage := &claircore.Package{
		Name:    "python3-requests",
		Version: "1:2.31.0-5.el9_4",
		Arch:    "x86_64",
	}

	fromPackage, err := ParsePackage(clairPackage)
	if err != nil {
		t.Fatal(err)
	}
	fromDNF, err := ParseDNFRow("python3-requests\t1\t2.31.0\t5.el9_4\tx86_64")
	if err != nil {
		t.Fatal(err)
	}
	if fromPackage.Key() != fromDNF.Key() {
		t.Fatalf("equivalent NEVRAs have different keys: %q != %q", fromPackage.Key(), fromDNF.Key())
	}
}

func TestNEVRAZeroEpochIsCanonical(t *testing.T) {
	withEpoch, err := ParseDNFRow("bash\t0\t5.1.8\t6.el9\taarch64")
	if err != nil {
		t.Fatal(err)
	}
	withoutEpoch, err := ParseDNFRow("bash\t\t5.1.8\t6.el9\taarch64")
	if err != nil {
		t.Fatal(err)
	}
	if withEpoch.Key() != withoutEpoch.Key() {
		t.Fatalf("zero and empty epochs have different keys: %q != %q", withEpoch.Key(), withoutEpoch.Key())
	}
}

func TestNEVRADifferentIdentityFieldsHaveDifferentKeys(t *testing.T) {
	base := NEVRA{Name: "pkg", Epoch: "0", Version: "1.2.3", Release: "4.el9", Arch: "noarch"}
	for name, variant := range map[string]NEVRA{
		"epoch":   {Name: "pkg", Epoch: "1", Version: "1.2.3", Release: "4.el9", Arch: "noarch"},
		"version": {Name: "pkg", Epoch: "0", Version: "1.2.4", Release: "4.el9", Arch: "noarch"},
		"release": {Name: "pkg", Epoch: "0", Version: "1.2.3", Release: "5.el9", Arch: "noarch"},
		"arch":    {Name: "pkg", Epoch: "0", Version: "1.2.3", Release: "4.el9", Arch: "x86_64"},
	} {
		if base.Key() == variant.Key() {
			t.Errorf("different %s produced the same key %q", name, base.Key())
		}
	}
}

func TestNEVRARejectsIncompleteValues(t *testing.T) {
	for _, row := range []string{
		"\t0\t1.0\t1.el9\tx86_64",
		"pkg\t0\t\t1.el9\tx86_64",
		"pkg\t0\t1.0\t\tx86_64",
		"pkg\t0\t1.0\t1.el9\t",
	} {
		if _, err := ParseDNFRow(row); err == nil {
			t.Errorf("ParseDNFRow(%q) succeeded", row)
		}
	}
}
