package main

import (
	"context"
	"os/signal"
	"syscall"

	"github.com/blesswinsamuel/ldap-sql-proxy/internal/config"
	"github.com/blesswinsamuel/ldap-sql-proxy/internal/ldapserver"
	"github.com/blesswinsamuel/ldap-sql-proxy/internal/logger"
	"github.com/blesswinsamuel/ldap-sql-proxy/internal/provider"
	"github.com/blesswinsamuel/ldap-sql-proxy/internal/server"

	"github.com/rs/zerolog"
)

func main() {
	// Parse options
	config, err := config.ParseConfig(nil)
	if err != nil {
		log := logger.NewLogger(zerolog.DebugLevel.String())
		log.Fatal().Err(err).Msg("failed to parse config")
	}

	// Setup logger
	log := logger.NewLogger(config.LogLevel)

	// Perform config validation
	config.Validate()

	provider, err := provider.NewSQLProvider(config.SQLProviderConfig)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to init SQL provider")
	}

	ldapserver := ldapserver.NewLdapServer(provider, ldapserver.Config{
		BindUsername: config.BindUsername,
		BindPassword: config.BindPassword,
		BaseDN:       config.BaseDN,
	})

	go ldapserver.Start(config.Host, config.LdapPort)
	defer ldapserver.Stop()

	// Build handler
	srv := server.NewServer(config, log, provider)

	// Start
	go srv.Start()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Info().Msg("server started")
	<-ctx.Done()
	log.Info().Msg("server stopping")
}
