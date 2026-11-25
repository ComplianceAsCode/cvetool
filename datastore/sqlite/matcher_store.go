package sqlite

import (
	"context"
	"database/sql"
	sqldriver "database/sql/driver"
	"errors"
	"fmt"
	"strconv"
	"strings"

	migrations "github.com/ComplianceAsCode/veseer/datastore/sqlite/migrations"
	version "github.com/hashicorp/go-version"
	"github.com/quay/claircore/datastore"
	"github.com/quay/zlog"
	"github.com/remind101/migrate"
	"modernc.org/sqlite"
)

// compile check datastore.MatcherStore implementation
var _ datastore.MatcherStore = (*sqliteMatcherStore)(nil)

type sqliteMatcherStore struct {
	conn *sql.DB
}

func NewSQLiteMatcherStore(DSN string, doMigration bool) (*sqliteMatcherStore, error) {
	sqlite.MustRegisterDeterministicScalarFunction("version_in", 2, _sqliteVersionIn)
	db, err := sql.Open("sqlite", DSN)
	if err != nil {
		return nil, err
	}

	if doMigration {
		migrator := migrate.NewMigrator(db)
		migrator.Table = migrations.MigrationTable
		if err := migrator.Exec(migrate.Up, migrations.MatcherMigrations...); err != nil {
			return nil, err
		}
	}
	return &sqliteMatcherStore{conn: db}, nil
}

// Initialized reports whether the vulnstore contains vulnerabilities.
func (ms *sqliteMatcherStore) Initialized(_ context.Context) (bool, error) {
	return true, nil
}

func (ms *sqliteMatcherStore) VacuumDatabase(ctx context.Context) error {
	ctx = zlog.ContextWithValues(ctx,
		"component", "datastore/sqlite/matcher_store.VacuumDatabase")
	zlog.Info(ctx).Msg("starting database vacuum")
	const (
		vacuum = "VACUUM;"
	)
	_, err := ms.conn.Exec(vacuum)
	if err != nil {
		return fmt.Errorf("failed to vacuum database: %v", err)
	}
	zlog.Info(ctx).Msg("finished database vacuum")
	return nil
}

type intVersion [10]int32

func (v *intVersion) String() string {
	var strs []string
	for _, p := range v {
		strs = append(strs, fmt.Sprint(p))
	}
	return strings.Join(strs, ".")
}

func (v *intVersion) FromString(str string) error {
	str = strings.Trim(str, "{}")
	sl := strings.Split(str, ",")
	for i := range sl {
		p, err := strconv.ParseInt(sl[i], 10, 32)
		if err != nil {
			return err
		}
		v[i] = int32(p)
	}
	return nil
}

// _sqliteVersionIn is registered and used to determine if a package version falls within a version
// range, the lower bound is considered inclusive and the upper is considered exclusive.

// vulnerable range is expected as a pair of 10 part, comma seperated version representations
// separated by `__` e.g. "{0,0,0,0,0,0,0,0,0,0}__{3,6,2147483647,0,0,0,0,0,0,0}"
func _sqliteVersionIn(ctx *sqlite.FunctionContext, args []sqldriver.Value) (sqldriver.Value, error) {
	if len(args) != 2 {
		return nil, errors.New("version_in must be passed 2 args")
	}
	pkgVer, ok := args[0].(string)
	if !ok {
		return nil, errors.New("could not convert package version arg to string")
	}
	vulnRange, ok := args[1].(string)
	if !ok {
		return nil, errors.New("could not convert vulnerable range arg to string")
	}

	var lower, upper intVersion
	ver, err := version.NewVersion(pkgVer)
	if err != nil {
		return false, fmt.Errorf("could not create version: %v", err)
	}

	vers := strings.Split(vulnRange, "__")
	if len(vers) != 2 {
		return false, fmt.Errorf("invalid version range %s", vulnRange)
	}
	err = lower.FromString(vers[0])
	if err != nil {
		return false, fmt.Errorf("could not create lower version: %v", err)
	}
	err = upper.FromString(vers[1])
	if err != nil {
		return false, fmt.Errorf("could not create upper version: %v", err)
	}
	constraints, err := version.NewConstraint(">=" + lower.String() + ", < " + upper.String())
	if err != nil {
		return false, fmt.Errorf("could not compare versions: %v", err)
	}
	if constraints.Check(ver) {
		return true, nil
	}
	return false, nil
}
