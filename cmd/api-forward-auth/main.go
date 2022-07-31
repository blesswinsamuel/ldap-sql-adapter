package main

import (
	"fmt"
	"net/http"

	"api-forward-auth/internal/config"
	"api-forward-auth/internal/logger"
	"api-forward-auth/internal/provider"
	"api-forward-auth/internal/server"

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

	provider, err := provider.NewAPIProvider(config.ApiURL)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to init API provider")
	}

	// Build handler
	handler := server.NewServer(config, provider, log)

	// Start
	log.Debug().Interface("config", config).Msg("Starting with config")
	log.Info().Msgf("Listening on %d", config.Port)
	addr := fmt.Sprintf("%s:%d", config.Host, config.Port)
	if err := http.ListenAndServe(addr, handler); err != nil {
		log.Error().Err(err).Msg("Failed to start server")
	}
}
