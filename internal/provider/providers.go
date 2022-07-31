package provider

import "context"

// Providers contains all the implemented providers
type Providers struct {
}

// Provider is used to authenticate users
type Provider interface {
	Authenticate(ctx context.Context, username string, password string) (User, error)
	FindByID(ctx context.Context, id string, ip string) (User, error)
	ResetPasswordInitiate(ctx context.Context, email string) error
	ResetPassword(ctx context.Context, email string, token string, newPassword string) error
}

// User is the authenticated user
type User map[string]interface{}
