package provider

import "context"

// Provider is used to authenticate users
type Provider interface {
	FindByUID(ctx context.Context, uid string) (User, error)
	FindGroups(ctx context.Context, uid string) ([]Group, error)
	UpdateUserPassword(ctx context.Context, uid string, password string) error
}

// User is the authenticated user
type User map[string]interface{}
type Group map[string]interface{}
