package catalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/quay/claircore"
	"github.com/quay/claircore/pkg/cpe"
)

const repositoryKey = "rhel-cpe-repository"

type Diagnostics struct {
	PackagesInspected int
	CatalogMatches    int
	UnmappedPackages  int
	RepositoriesAdded int
}

func EnrichIndexReport(ctx context.Context, report *claircore.IndexReport, reader Reader) (Diagnostics, error) {
	var diagnostics Diagnostics
	if report == nil {
		return diagnostics, fmt.Errorf("nil index report")
	}
	if reader == nil {
		return diagnostics, fmt.Errorf("nil catalog reader")
	}
	if report.Repositories == nil {
		report.Repositories = map[string]*claircore.Repository{}
	}

	for packageID, pkg := range report.Packages {
		diagnostics.PackagesInspected++
		nevra, err := ParsePackage(pkg)
		if err != nil {
			diagnostics.UnmappedPackages++
			continue
		}
		matches, err := reader.Lookup(ctx, nevra)
		if err != nil {
			return diagnostics, fmt.Errorf("lookup package %q: %w", packageID, err)
		}
		if len(matches) == 0 {
			diagnostics.UnmappedPackages++
			continue
		}
		diagnostics.CatalogMatches += len(matches)
		validatedMatches := make([]struct {
			match Match
			cpe   cpe.WFN
		}, len(matches))
		for i, match := range matches {
			wfn, err := cpe.Unbind(match.CPE)
			if err != nil {
				return diagnostics, fmt.Errorf("invalid catalog CPE %q: %w", match.CPE, err)
			}
			validatedMatches[i] = struct {
				match Match
				cpe   cpe.WFN
			}{match: match, cpe: wfn}
		}

		for _, env := range report.Environments[packageID] {
			if env == nil {
				continue
			}
			for _, validated := range validatedMatches {
				if hasRepositoryID(env.RepositoryIDs, validated.match.RepositoryID) {
					continue
				}
				repositoryID := syntheticRepositoryID(validated.match.RepositoryID, validated.match.CPE)
				if _, ok := report.Repositories[repositoryID]; !ok {
					report.Repositories[repositoryID] = &claircore.Repository{
						ID:  repositoryID,
						Key: repositoryKey,
						URI: validated.match.RepositoryID,
						CPE: validated.cpe,
					}
					diagnostics.RepositoriesAdded++
				}
				if !hasRepositoryID(env.RepositoryIDs, repositoryID) {
					env.RepositoryIDs = append(env.RepositoryIDs, repositoryID)
				}
			}
		}
	}
	return diagnostics, nil
}

func syntheticRepositoryID(repositoryID, cpeValue string) string {
	digest := sha256.Sum256([]byte(repositoryID + "\x00" + cpeValue))
	return repositoryKey + "-" + hex.EncodeToString(digest[:])
}

func hasRepositoryID(repositoryIDs []string, wanted string) bool {
	for _, repositoryID := range repositoryIDs {
		if repositoryID == wanted {
			return true
		}
	}
	return false
}
