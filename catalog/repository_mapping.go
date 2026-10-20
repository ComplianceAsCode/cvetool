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
	data             map[string][]string
	repoRelativeURLs map[string][]string
	source           string
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

func (m RepositoryMapping) forRHELRelease(repositoryIDs []string, releaseVersion, architecture string) (RepositoryMapping, error) {
	filtered := RepositoryMapping{
		data:   make(map[string][]string, len(repositoryIDs)),
		source: m.source,
	}
	for _, repositoryID := range repositoryIDs {
		cpes, ok := m.Lookup(repositoryID)
		if !ok {
			continue
		}
		selected, err := m.cpesForRHELRelease(repositoryID, cpes, releaseVersion, architecture)
		if err != nil {
			return RepositoryMapping{}, err
		}
		filtered.data[repositoryID] = selected
	}
	return filtered, nil
}

// cpesForRHELRelease prefers Red Hat's version-suffixed repository entry.
// Aggregate rows can include CPEs for other release minors and streams.
func (m RepositoryMapping) cpesForRHELRelease(repositoryID string, cpes []string, releaseVersion, architecture string) ([]string, error) {
	targetReleaseVersion := strings.TrimSpace(releaseVersion)
	targetCPEVersion := rhelCPEVersion(targetReleaseVersion)
	if !m.requiresRHELReleaseSpecificMapping(repositoryID) {
		return cpes, nil
	}
	if targetCPEVersion != "" {
		versionSpecificID := repositoryID + "__" + strings.ReplaceAll(targetCPEVersion, ".", "_DOT_")
		if architecture != "" {
			if selected, ok := m.Lookup(versionSpecificID + "__" + architecture); ok {
				return selected, nil
			}
		}
		if selected, ok := m.Lookup(versionSpecificID); ok {
			return selected, nil
		}
	}

	if targetCPEVersion == "" {
		if targetReleaseVersion == "" {
			return nil, fmt.Errorf("target RHEL release is required to select a CPE for repository %q", repositoryID)
		}
		return nil, fmt.Errorf("target RHEL release %q must include a numeric major.minor version to select a CPE for repository %q", targetReleaseVersion, repositoryID)
	}
	return nil, fmt.Errorf("repository %q has no version-specific CPE mapping for target release %q", repositoryID, targetCPEVersion)
}

func (m RepositoryMapping) requiresRHELReleaseSpecificMapping(repositoryID string) bool {
	if isRHELEUSRepositoryID(repositoryID) || hasRHELMinorRepositoryURL(m.repoRelativeURLs[repositoryID]) {
		return true
	}
	prefix := repositoryID + "__"
	for id := range m.data {
		if strings.HasPrefix(id, prefix) {
			return true
		}
	}
	return false
}

func hasRHELMinorRepositoryURL(urls []string) bool {
	for _, repositoryURL := range urls {
		parts := strings.Split(strings.Trim(repositoryURL, "/"), "/")
		if len(parts) < 4 || parts[0] != "content" || parts[1] == "dist" {
			continue
		}
		major := strings.TrimPrefix(parts[2], "rhel")
		if !allASCIIDigits(major) {
			continue
		}
		version := parts[3]
		if rhelCPEVersion(version) != version {
			continue
		}
		versionMajor, _, _ := strings.Cut(version, ".")
		if versionMajor == major {
			return true
		}
	}
	return false
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
			CPEs             []string `json:"cpes"`
			RepoRelativeURLs []string `json:"repo_relative_urls"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return RepositoryMapping{}, fmt.Errorf("decode repository mapping JSON: %w", err)
	}
	mapping := RepositoryMapping{
		data:             make(map[string][]string),
		repoRelativeURLs: make(map[string][]string),
		source:           source,
	}
	for id, repository := range payload.Data {
		mapping.data[id] = append([]string(nil), repository.CPEs...)
		mapping.repoRelativeURLs[id] = append([]string(nil), repository.RepoRelativeURLs...)
	}
	return mapping, nil
}

func (m RepositoryMapping) Source() string { return m.source }

func hashJSON(value any) string {
	data, _ := json.Marshal(value)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
