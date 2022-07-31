package logger

import (
	"os"

	"github.com/rs/zerolog"
)

// NewLogger creates a new logger based on the current configuration
func NewLogger(logLevel string) zerolog.Logger {
	// Setup logger
	log := zerolog.New(os.Stderr).With().Timestamp().Logger()
	ll, err := zerolog.ParseLevel(logLevel)
	if err != nil {
		ll = zerolog.DebugLevel
	}
	return log.With().Logger().Level(ll)
}
