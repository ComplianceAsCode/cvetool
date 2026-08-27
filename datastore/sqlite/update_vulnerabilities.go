package sqlite

import (
	"bytes"
	"context"
	"crypto/md5"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/quay/claircore"
	"github.com/quay/claircore/datastore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/zlog"
)

func (ms *sqliteMatcherStore) DeltaUpdateVulnerabilities(ctx context.Context, updater string, fp driver.Fingerprint, vulns []*claircore.Vulnerability, deletedVulns []string) (uuid.UUID, error) {
	zlog.Debug(ctx).Msg(">>> DeltaUpdateVulnerabilities")
	iterVulns := func(yield func(*claircore.Vulnerability, error) bool) {
		for i := range vulns {
			if !yield(vulns[i], nil) {
				break
			}
		}
	}
	delVulns := func(yield func(string, error) bool) {
		for _, s := range deletedVulns {
			if !yield(s, nil) {
				break
			}
		}
	}
	return ms.updateVulnerabilities(ctx, updater, fp, iterVulns, delVulns)
}

// UpdateVulnerabilities creates a new UpdateOperation, inserts the provided
// vulnerabilities, and ensures vulnerabilities from previous updates are
// not queried by clients.
func (ms *sqliteMatcherStore) UpdateVulnerabilities(ctx context.Context, updaterName string, fp driver.Fingerprint, vs []*claircore.Vulnerability) (uuid.UUID, error) {
	zlog.Debug(ctx).Msg(">>> UpdateVulnerabilities")
	vsIter := func(yield func(*claircore.Vulnerability, error) bool) {
		for i := range vs {
			if !yield(vs[i], nil) {
				break
			}
		}
	}

	return ms.UpdateVulnerabilitiesIter(ctx, updaterName, fp, vsIter)
}

// UpdateVulnerabilitiesIter performs the same operation as
// UpdateVulnerabilities, but accepting an iterator function.
func (ms *sqliteMatcherStore) UpdateVulnerabilitiesIter(ctx context.Context, updater string, fp driver.Fingerprint, vsIter datastore.VulnerabilityIter) (uuid.UUID, error) {
	return ms.updateVulnerabilities(ctx, updater, fp, vsIter, nil)
}

func (ms *sqliteMatcherStore) updateVulnerabilities(ctx context.Context, updater string, fingerprint driver.Fingerprint, vulnIter datastore.VulnerabilityIter, delIter datastore.Iter[string]) (uuid.UUID, error) {
	const (
		// Create makes a new update operation and returns the reference and ID.
		create = `INSERT INTO update_operation (updater, fingerprint, kind, ref) VALUES ($1, $2, 'vulnerability', $3) RETURNING id;`
		// Select existing vulnerabilities that are associated with the latest_update_operation.
		// Name lives in metadata (name_id); selecting "name" from vuln is wrong on SQLite —
		// a missing double-quoted identifier becomes a string literal, so every row is keyed
		// as "name" and delta carry-forward never drops updated/deleted advisories.
		selectExisting = `
		SELECT
			"name"."value",
			"vuln"."id"
		FROM
			"vuln"
			INNER JOIN "metadata" AS "name" ON ("vuln"."name_id" = "name"."id")
			INNER JOIN "uo_vuln" ON ("vuln"."id" = "uo_vuln"."vuln")
			INNER JOIN "latest_update_operations" ON (
			"latest_update_operations"."id" = "uo_vuln"."uo"
			)
		WHERE
			(
			"latest_update_operations"."kind" = 'vulnerability'
			)
		AND
			(
			"vuln"."updater" = $1
			)`
		// assocExisting associates existing vulnerabilities with new update operations
		assocExisting = `INSERT INTO uo_vuln (uo, vuln) VALUES ($1, $2) ON CONFLICT DO NOTHING;`
		// Insert attempts to create a new vulnerability. It fails silently.
		insert = `
		INSERT INTO vuln (
			hash_kind, hash,
			updater, issued, links, severity, normalized_severity,
			package_name, package_version, package_module, package_arch, package_kind,
			dist_id, dist_name, dist_version, dist_version_code_name, dist_version_id, dist_arch, dist_cpe, dist_pretty_name,
			repo_name, repo_key, repo_uri,
			fixed_in_version, arch_operation, version_kind, vulnerable_range, description_id, name_id
		) VALUES (
		  $1, $2,
		  $3, $4, $5, $6, $7, $8, $9,
		  $10, $11, $12, $13, $14,
		  $15, $16, $17, $18, $19, $20, $21, $22,
		  $23, $24, $25,
		  $26, $27, $28, $29
		)
		ON CONFLICT (hash_kind, hash) DO NOTHING;`
		assoc = `
		INSERT INTO uo_vuln (uo, vuln) VALUES (
			$3,
			(SELECT id FROM vuln WHERE hash_kind = $1 AND hash = $2))
		ON CONFLICT DO NOTHING;`
	)

	var uoID uint64
	var ref = uuid.New()

	tx, err := ms.conn.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Rollback()

	delta := delIter != nil
	oldVulns := make(map[string][]string)

	if delta {
		zlog.Debug(ctx).Msg("updateVulnerabilities (delta, get)")
		// Get existing vulns
		rows, err := ms.conn.QueryContext(ctx, selectExisting, updater)
		if err != nil {
			return uuid.Nil, fmt.Errorf("failed to get existing vulns: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var tmpID int64
			var ID, name string
			err := rows.Scan(
				&name,
				&tmpID,
			)

			ID = strconv.FormatInt(tmpID, 10)
			if err != nil {
				return uuid.Nil, fmt.Errorf("failed to scan vulnerability: %w", err)
			}
			oldVulns[name] = append(oldVulns[name], ID)
		}
		if err := rows.Err(); err != nil {
			return uuid.Nil, fmt.Errorf("error reading existing vulnerabilities: %w", err)
		}

		if len(oldVulns) > 0 {
			vulnIter(func(v *claircore.Vulnerability, _ error) bool {
				// If we have an existing vuln in the new batch
				// delete it from the oldVulns map so it doesn't
				// get associated with the new update_operation.
				delete(oldVulns, v.Name)
				return true
			})
			delIter(func(delName string, _ error) bool {
				// If we have an existing vuln that has been signaled
				// as deleted by the updater then delete it so it doesn't
				// get associated with the new update_operation.
				delete(oldVulns, delName)
				return true
			})
		}
	}

	// Create new update operation
	if err := tx.QueryRowContext(ctx, create, updater, fingerprint, ref.String()).Scan(&uoID); err != nil {
		zlog.Error(ctx).Err(err)
		return uuid.Nil, fmt.Errorf("failed to create update_operation: %w", err)
	}
	zlog.Debug(ctx).
		Str("ref", ref.String()).
		Msg("created update operation")

	if delta {
		zlog.Debug(ctx).Msg("updateVulnerabilities (delta, assoc)")
		// Associate already existing vulnerabilities with new update_operation.
		for _, vs := range oldVulns {
			for _, vID := range vs {
				_, err := tx.ExecContext(ctx, assocExisting, uoID, vID)
				if err != nil {
					return uuid.Nil, fmt.Errorf("could not update old vulnerability with new UO: %w", err)
				}
			}
		}
	}

	skipCt := 0
	vulnCt := 0

	vulnIter(func(vuln *claircore.Vulnerability, iterErr error) bool {
		if iterErr != nil {
			err = fmt.Errorf("iterating on vulnerabilities: %w", iterErr)
			return false
		}

		// Get or save description
		var descID int64
		descID, err = getMetadata(ctx, tx, "description", vuln.Description)
		if err != nil {
			err = fmt.Errorf("failed to get description: %w", err)
			return false
		}
		var nameID int64
		nameID, err = getMetadata(ctx, tx, "name", vuln.Name)
		if err != nil {
			err = fmt.Errorf("failed to get name: %w", err)
			return false
		}
		vulnCt++
		if vuln.Package == nil || vuln.Package.Name == "" {
			skipCt++
			return true
		}

		pkg := vuln.Package
		dist := vuln.Dist
		repo := vuln.Repo
		if dist == nil {
			dist = &claircore.Distribution{}
		}
		if repo == nil {
			repo = &claircore.Repository{}
		}
		hashKind, hash := md5Vuln(vuln)
		vKind, vrLower, vrUpper := rangefmt(vuln.Range)

		if _, err = tx.ExecContext(ctx, insert,
			hashKind, hash,
			vuln.Updater, vuln.Issued.Format(time.RFC3339), vuln.Links, vuln.Severity, vuln.NormalizedSeverity,
			pkg.Name, pkg.Version, pkg.Module, pkg.Arch, pkg.Kind,
			dist.DID, dist.Name, dist.Version, dist.VersionCodeName, dist.VersionID, dist.Arch, &dist.CPE, dist.PrettyName,
			repo.Name, repo.Key, repo.URI,
			vuln.FixedInVersion, vuln.ArchOperation, vKind, strings.Join([]string{vrLower, vrUpper}, "__"), descID, nameID,
		); err != nil {
			err = fmt.Errorf("failed to insert vulnerability: %w", err)
			return false
		}
		if _, err = tx.ExecContext(ctx, assoc, hashKind, hash, uoID); err != nil {
			err = fmt.Errorf("failed to assoc vulnerability: %w", err)
			return false
		}

		return true
	})

	if err != nil {
		return uuid.Nil, err
	}

	if err := tx.Commit(); err != nil {
		return uuid.Nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	zlog.Debug(ctx).
		Str("ref", ref.String()).
		Int("skipped", skipCt).
		Int("inserted", vulnCt-skipCt).
		Msg("update_operation committed")

	return ref, nil
}

func getMetadata(ctx context.Context, tx *sql.Tx, kind string, val string) (int64, error) {
	var metadataID int64
	s := md5.Sum([]byte(val))
	const (
		get = `
		SELECT id FROM metadata
		WHERE kind = $1
		AND hash_kind = $2
		AND hash = $3`
		insert = `
		INSERT INTO metadata (
			kind, hash_kind, hash, value
		) VALUES (
			$1, $2, $3, $4
		)
		ON CONFLICT (kind, hash_kind, hash) DO NOTHING
		RETURNING id;`
	)
	err := tx.QueryRowContext(ctx, get, kind, "md5", s[:], val).Scan(&metadataID)
	switch {
	case err == sql.ErrNoRows:
		if err := tx.QueryRowContext(ctx, insert, kind, "md5", s[:], val).Scan(&metadataID); err != nil {
			return 0, fmt.Errorf("failed to scan description: %v", err)
		}
	case err != nil:
		return 0, err
	}
	return metadataID, nil
}

// Md5Vuln creates an md5 hash from the members of the passed-in Vulnerability,
// giving us a stable, context-free identifier for this revision of the
// Vulnerability.
func md5Vuln(v *claircore.Vulnerability) (string, []byte) {
	var b bytes.Buffer
	b.WriteString(v.Name)
	b.WriteString(v.Description)
	b.WriteString(v.Issued.String())
	b.WriteString(v.Links)
	b.WriteString(v.Severity)
	if v.Package != nil {
		b.WriteString(v.Package.Name)
		b.WriteString(v.Package.Version)
		b.WriteString(v.Package.Module)
		b.WriteString(v.Package.Arch)
		b.WriteString(v.Package.Kind)
	}
	if v.Dist != nil {
		b.WriteString(v.Dist.DID)
		b.WriteString(v.Dist.Name)
		b.WriteString(v.Dist.Version)
		b.WriteString(v.Dist.VersionCodeName)
		b.WriteString(v.Dist.VersionID)
		b.WriteString(v.Dist.Arch)
		b.WriteString(v.Dist.CPE.BindFS())
		b.WriteString(v.Dist.PrettyName)
	}
	if v.Repo != nil {
		b.WriteString(v.Repo.Name)
		b.WriteString(v.Repo.Key)
		b.WriteString(v.Repo.URI)
	}
	b.WriteString(v.ArchOperation.String())
	b.WriteString(v.FixedInVersion)
	if k, l, u := rangefmt(v.Range); k != nil {
		b.WriteString(*k)
		b.WriteString(l)
		b.WriteString(u)
	}
	s := md5.Sum(b.Bytes())
	return "md5", s[:]
}

func rangefmt(r *claircore.Range) (kind *string, lower, upper string) {
	lower, upper = "{}", "{}"
	if r == nil || r.Lower.Kind != r.Upper.Kind {
		return kind, lower, upper
	}

	kind = &r.Lower.Kind // Just tested the both kinds are the same.
	v := &r.Lower
	var buf strings.Builder
	b := make([]byte, 0, 16) // 16 byte wide scratch buffer

	buf.WriteByte('{')
	for i := range 10 {
		if i != 0 {
			buf.WriteByte(',')
		}
		buf.Write(strconv.AppendInt(b, int64(v.V[i]), 10))
	}
	buf.WriteByte('}')
	lower = buf.String()
	buf.Reset()
	v = &r.Upper
	buf.WriteByte('{')
	for i := range 10 {
		if i != 0 {
			buf.WriteByte(',')
		}
		buf.Write(strconv.AppendInt(b, int64(v.V[i]), 10))
	}
	buf.WriteByte('}')
	upper = buf.String()

	return kind, lower, upper
}
