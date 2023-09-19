package provider

import (
	"context"
	"fmt"
)

var (
	ErrUserNotFound = fmt.Errorf("user not found")
)

// Provider is used to authenticate users
type Provider interface {
	FindUserPasswordByUsername(ctx context.Context, username string) ([]byte, error)
	FindUserByUsernameOrEmail(ctx context.Context, username string, email string) (User, error)
	FindUserGroups(ctx context.Context, username string) ([]Group, error)
	UpdateUserPassword(ctx context.Context, username string, password string) error
}

// User is the authenticated user
type User map[string]interface{}
type Group map[string]interface{}
