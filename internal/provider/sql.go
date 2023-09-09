package provider

import (
	"context"
	"fmt"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

type SQLProviderConfig struct {
	DatabaseURL string `long:"database-url" env:"DATABASE_URL"`

	SQLGetUserQuery        string `long:"sql-get-user-query" env:"SQL_GET_USER_QUERY" default:""`
	SQLGetUserGroupsQuery  string `long:"sql-get-user-groups-query" env:"SQL_GET_USER_GROUPS_QUERY" default:""`
	SQLUpdatePasswordQuery string `long:"sql-update-password-query" env:"SQL_UPDATE_PASSWORD_QUERY" default:""`
}

type SQLProvider struct {
	db     *sqlx.DB
	config SQLProviderConfig
}

func NewSQLProvider(config SQLProviderConfig) (*SQLProvider, error) {
	db, err := sqlx.Open("postgres", config.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("unable to open database: %w", err)
	}
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("unable to ping database: %w", err)
	}
	return &SQLProvider{db: db, config: config}, nil
}

func (p *SQLProvider) FindByUID(ctx context.Context, uid string) (User, error) {
	rows, err := p.db.NamedQueryContext(ctx, p.config.SQLGetUserQuery, map[string]any{"uid": uid})
	// givenname, sn, displayname, mail, uid, password
	if err != nil {
		return nil, fmt.Errorf("unable to get user: %w", err)
	}
	defer rows.Close()
	users, err := rowsToMap(rows)
	if err != nil {
		return nil, fmt.Errorf("unable to get columns: %w", err)
	}
	if len(users) == 0 {
		return nil, fmt.Errorf("user not found")
	}
	return users[0], nil
}

func (p *SQLProvider) FindGroups(ctx context.Context, uid string) ([]Group, error) {
	rows, err := p.db.NamedQueryContext(ctx, p.config.SQLGetUserGroupsQuery, map[string]any{"uid": uid})
	if err != nil {
		return nil, fmt.Errorf("unable to get groups: %w", err)
	}
	defer rows.Close()
	groupRows, err := rowsToMap(rows)
	if err != nil {
		return nil, fmt.Errorf("unable to get columns: %w", err)
	}
	groups := []Group{}
	for _, group := range groupRows {
		groups = append(groups, Group(group))
	}
	return groups, nil
}

func (p *SQLProvider) UpdateUserPassword(ctx context.Context, uid string, password string) error {
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
