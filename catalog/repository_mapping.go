package catalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/quay/claircore/pkg/cpe"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
)

const defaultRepositoryMappingURL = "https://access.redhat.com/security/data/metrics/repository-to-cpe.json"

type RepositoryMapping struct {
	data   map[string][]string
	source string
}

func (m RepositoryMapping) Lookup(repositoryID string) ([]string, bool) {
	cpes, ok := m.data[repositoryID]
	return append([]string(nil), cpes...), ok
}

func (m RepositoryMapping) Validate(repositoryID string) error {
	cpes, ok := m.Lookup(repositoryID)
	if !ok {
		return fmt.Errorf("repository %q is absent from mapping", repositoryID)
	}
	if len(cpes) == 0 {
		return fmt.Errorf("repository %q has no CPEs", repositoryID)
	}
	for _, value := range cpes {
		if _, err := cpe.Unbind(value); err != nil {
			return fmt.Errorf("repository %q has invalid CPE %q: %w", repositoryID, value, err)
		}
	}
	return nil
}

func (m RepositoryMapping) forRHELRelease(repositoryIDs []string, releaseVersion string) (RepositoryMapping, error) {
	filtered := RepositoryMapping{
		data:   make(map[string][]string, len(repositoryIDs)),
		source: m.source,
	}
	for _, repositoryID := range repositoryIDs {
		cpes, ok := m.Lookup(repositoryID)
		if !ok {
			continue
		}
		selected, err := cpesForRHELRelease(repositoryID, cpes, releaseVersion)
		if err != nil {
			return RepositoryMapping{}, err
		}
		filtered.data[repositoryID] = selected
	}
	return filtered, nil
}

func cpesForRHELRelease(repositoryID string, cpes []string, releaseVersion string) ([]string, error) {
	targetReleaseVersion := strings.TrimSpace(releaseVersion)
	releaseVersion = rhelCPEVersion(targetReleaseVersion)
	targetCPEVersion := ""
	if releaseVersion != "" {
		target, err := cpe.Unbind("cpe:/o:redhat:rhel_eus:" + releaseVersion)
		if err != nil {
			return nil, fmt.Errorf("invalid target RHEL release %q: %w", releaseVersion, err)
		}
		targetCPEVersion = target.Attr[cpe.Version].V
	}
	selectedEUS := make([]string, 0, len(cpes))
	hasEUSCPE := false
	for _, value := range cpes {
		wfn, err := cpe.Unbind(value)
		if err != nil {
			return nil, fmt.Errorf("repository %q has invalid CPE %q: %w", repositoryID, value, err)
		}
		product := wfn.Attr[cpe.Product]
		version := wfn.Attr[cpe.Version]
		if product.Kind == cpe.ValueSet && product.V == "rhel_eus" {
			hasEUSCPE = true
			if releaseVersion == "" {
				if targetReleaseVersion == "" {
					return nil, fmt.Errorf("target RHEL release is required to select a CPE for EUS repository %q", repositoryID)
				}
				return nil, fmt.Errorf("target RHEL release %q must include a numeric major.minor version to select a CPE for EUS repository %q", targetReleaseVersion, repositoryID)
			}
			if version.Kind == cpe.ValueSet && version.V == targetCPEVersion {
				selectedEUS = append(selectedEUS, value)
			}
		}
	}
	if !hasEUSCPE {
		if isRHELEUSRepositoryID(repositoryID) {
			return nil, fmt.Errorf("EUS repository %q has no EUS CPE in the repository mapping", repositoryID)
		}
		return cpes, nil
	}
	if len(selectedEUS) == 0 {
		return nil, fmt.Errorf("repository %q has no EUS CPE for target release %q", repositoryID, releaseVersion)
	}
	return selectedEUS, nil
}

func isRHELEUSRepositoryID(repositoryID string) bool {
	if !strings.HasPrefix(repositoryID, "rhel-") {
		return false
	}

	majorAndRest := strings.TrimPrefix(repositoryID, "rhel-")
	major, rest, ok := strings.Cut(majorAndRest, "-")
	if !ok || !allASCIIDigits(major) || strings.Contains(rest, "-extended-eus-") {
		return false
	}
	return strings.Contains(rest, "-eus-")
}

func rhelCPEVersion(releaseVersion string) string {
	parts := strings.Split(strings.TrimSpace(releaseVersion), ".")
	if len(parts) < 2 || !allASCIIDigits(parts[0]) || !allASCIIDigits(parts[1]) {
		return ""
	}
	return parts[0] + "." + parts[1]
}

func (m RepositoryMapping) Fingerprint(repositoryIDs []string) string {
	type entry struct {
		ID   string   `json:"id"`
		CPEs []string `json:"cpes"`
	}
	entries := make([]entry, 0, len(repositoryIDs))
	ids := append([]string(nil), repositoryIDs...)
	sort.Strings(ids)
	for _, id := range ids {
		cpes := append([]string(nil), m.data[id]...)
		sort.Strings(cpes)
		entries = append(entries, entry{ID: id, CPEs: cpes})
	}
	return hashJSON(entries)
}

func LoadRepositoryMapping(ctx context.Context, file, url string) (RepositoryMapping, error) {
	source := file
	if source == "" {
		source = url
	}
	if source == "" {
		source = defaultRepositoryMappingURL
	}
	var data []byte
	var err error
	if file != "" {
		data, err = os.ReadFile(file)
	} else {
		request, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
		if requestErr != nil {
			return RepositoryMapping{}, fmt.Errorf("create repository mapping request: %w", requestErr)
		}
		var response *http.Response
		response, err = http.DefaultClient.Do(request)
		if err == nil {
			defer response.Body.Close()
			if response.StatusCode < 200 || response.StatusCode >= 300 {
				err = fmt.Errorf("mapping URL returned %s", response.Status)
			} else {
				data, err = io.ReadAll(response.Body)
			}
		}
	}
	if err != nil {
		return RepositoryMapping{}, fmt.Errorf("read repository mapping %s: %w", source, err)
	}
	var payload struct {
		Data map[string]struct {
			CPEs []string `json:"cpes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return RepositoryMapping{}, fmt.Errorf("decode repository mapping JSON: %w", err)
	}
	mapping := RepositoryMapping{data: make(map[string][]string), source: source}
	for id, repository := range payload.Data {
		mapping.data[id] = append([]string(nil), repository.CPEs...)
	}
	return mapping, nil
}

func (m RepositoryMapping) Source() string { return m.source }

func hashJSON(value any) string {
	data, _ := json.Marshal(value)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
