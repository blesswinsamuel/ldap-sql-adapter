package provider

import (
	"context"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	sqlQueryDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name: "ldap_sql_adapter_sql_query_duration_seconds",
		Help: "Duration of SQL query requests.",
	}, []string{"query_name", "status"})
)

type SQLProviderConfig struct {
	DatabaseURL string `long:"database-url" env:"DATABASE_URL"`

	SQLGetUserPasswordByUsernameQuery string `long:"sql-get-user-password-by-username-query" env:"SQL_GET_USER_PASSWORD_BY_USERNAME_QUERY" default:""`
	SQLGetUserByUsernameOrEmailQuery  string `long:"sql-get-user-by-username-or-email-query" env:"SQL_GET_USER_BY_USERNAME_OR_EMAIL_QUERY" default:""`
	SQLGetUserGroupsQuery             string `long:"sql-get-user-groups-query" env:"SQL_GET_USER_GROUPS_QUERY" default:""`
	SQLUpdatePasswordQuery            string `long:"sql-update-password-query" env:"SQL_UPDATE_PASSWORD_QUERY" default:""`
}

type SQLProvider struct {
	db     *sqlx.DB
	config SQLProviderConfig
}

func logMetric(queryName string) func(err error) {
	startTime := time.Now()
	return func(err error) {
		status := "success"
		if err != nil {
			status = "error"
		}
		sqlQueryDuration.WithLabelValues(queryName, status).Observe(time.Since(startTime).Seconds())
	}
}

func NewSQLProvider(config SQLProviderConfig) (*SQLProvider, error) {
	db, err := sqlx.Open("postgres", config.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("unable to open database: %w", err)
	}
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("unable to ping database: %w", err)
	}
	if config.SQLGetUserPasswordByUsernameQuery == "" || config.SQLGetUserByUsernameOrEmailQuery == "" || config.SQLGetUserGroupsQuery == "" || config.SQLUpdatePasswordQuery == "" {
		return nil, fmt.Errorf("sql queries not provided")
	}
	return &SQLProvider{db: db, config: config}, nil
}

func (p *SQLProvider) Ping(ctx context.Context) (err error) {
	defer logMetric("Ping")(err)
	return p.db.PingContext(ctx)
}

func (p *SQLProvider) FindUserPasswordByUsername(ctx context.Context, uid string) (passwordBytes []byte, err error) {
	defer logMetric("FindUserPasswordByUsername")(err)
	rows, err := p.db.NamedQueryContext(ctx, p.config.SQLGetUserPasswordByUsernameQuery, map[string]any{"uid": uid})
	// password
	if err != nil {
		return nil, fmt.Errorf("unable to get user: %w", err)
	}
	defer rows.Close()
	users, err := rowsToMap(rows)
	if err != nil {
		return nil, fmt.Errorf("unable to get columns: %w", err)
	}
	if len(users) != 1 {
		return nil, ErrUserNotFound
	}
	user := users[0]
	password := user["password"].(string)
	return []byte(password), nil
}

func (p *SQLProvider) FindUserByUsernameOrEmail(ctx context.Context, uid string, email string) (user User, err error) {
	defer logMetric("FindUserByUsernameOrEmail")(err)
	rows, err := p.db.NamedQueryContext(ctx, p.config.SQLGetUserByUsernameOrEmailQuery, map[string]any{"uid": uid, "email": email})
	// displayname, email, uid // givenname, sn
	if err != nil {
		return nil, fmt.Errorf("unable to get user: %w", err)
	}
	defer rows.Close()
	users, err := rowsToMap(rows)
	if err != nil {
		return nil, fmt.Errorf("unable to get columns: %w", err)
	}
	if len(users) != 1 {
		return nil, ErrUserNotFound
	}
	return users[0], nil
}

func (p *SQLProvider) FindUserGroups(ctx context.Context, uid string) (groups []Group, err error) {
	defer logMetric("FindUserGroups")(err)
	rows, err := p.db.NamedQueryContext(ctx, p.config.SQLGetUserGroupsQuery, map[string]any{"uid": uid})
	if err != nil {
		return nil, fmt.Errorf("unable to get groups: %w", err)
	}
	defer rows.Close()
	groupRows, err := rowsToMap(rows)
	if err != nil {
		return nil, fmt.Errorf("unable to get columns: %w", err)
	}
	groups = []Group{}
	for _, group := range groupRows {
		groups = append(groups, Group(group))
	}
	return groups, nil
}

func (p *SQLProvider) UpdateUserPassword(ctx context.Context, uid string, password string) (err error) {
	defer logMetric("UpdateUserPassword")(err)
	res, err := p.db.NamedExecContext(ctx, p.config.SQLUpdatePasswordQuery, map[string]any{"uid": uid, "password": password})
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}
	if rows, err := res.RowsAffected(); err != nil || rows == 0 {
		return fmt.Errorf("unable to update password")
	}
	return nil
}

func rowsToMap(rows *sqlx.Rows) ([]map[string]interface{}, error) {
	user := []map[string]any{}
	for rows.Next() {
		resSlice, err := rows.SliceScan()
		if err != nil {
			return nil, fmt.Errorf("unable to scan user: %w", err)
		}
		u := map[string]interface{}{}
		cols, err := rows.Columns()
		if err != nil {
			return nil, fmt.Errorf("unable to get columns: %w", err)
		}
		for i, col := range cols {
			u[col] = resSlice[i]
		}
		user = append(user, u)
	}
	return user, nil
}
