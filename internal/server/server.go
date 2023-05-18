package server

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/blesswinsamuel/ldap-sql-proxy/internal/config"
)

// Server contains router and handler methods
type Server struct {
	router *mux.Router
	logger zerolog.Logger
	config *config.Config
}

// NewServer creates a new server object and builds router
func NewServer(cfg *config.Config, logger zerolog.Logger) *Server {
	s := &Server{
		router: mux.NewRouter(),
		logger: logger,
		config: cfg,
	}

	s.buildRoutes()

	err := s.router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		pathTemplate, _ := route.GetPathTemplate()
		pathRegexp, _ := route.GetPathRegexp()
		queriesTemplates, _ := route.GetQueriesTemplates()
		queriesRegexps, _ := route.GetQueriesRegexp()
		methods, _ := route.GetMethods()
		s.logger.Info().Fields([]interface{}{
			"pathtemplate", pathTemplate,
			"pathregexp", pathRegexp,
			"queriestemplate", strings.Join(queriesTemplates, ","),
			"queriesregexp", strings.Join(queriesRegexps, ","),
			"method", strings.Join(methods, ","),
		}).Msgf("")
		return nil
	})

	if err != nil {
		s.logger.Error().Err(err).Msg("")
	}

	return s
}

func (s *Server) Start() {
	log.Debug().Interface("config", s.config).Msg("Starting with config")
	log.Info().Msgf("Listening on %d", s.config.HttpPort)
	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.HttpPort)
	if err := http.ListenAndServe(addr, s); err != nil {
		log.Panic().Err(err).Msg("Failed to start server")
	}
}

func (s *Server) buildRoutes() {
	s.router.Use(prometheusMiddleware)
	s.router.Use(s.loggerMiddleware)

	s.router.Handle("/metrics", promhttp.Handler())
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

func (s *Server) loggerMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Create logger
		logger := s.logger.With().Fields(map[string]interface{}{
			"handler":   r.URL.Path,
			"method":    r.Header.Get("X-Forwarded-Method"),
			"proto":     r.Header.Get("X-Forwarded-Proto"),
			"host":      r.Header.Get("X-Forwarded-Host"),
			"uri":       r.Header.Get("X-Forwarded-Uri"),
			"source_ip": r.Header.Get("X-Forwarded-For"),
		}).Logger()

		// Log request
		logger.Debug().Interface("cookies", r.Cookies()).Msg("Received request")

		r = r.WithContext(context.WithValue(r.Context(), loggerCtx{}, logger))

		h.ServeHTTP(w, r)
	})
}

type loggerCtx struct{}

// func getLogger(ctx context.Context) zerolog.Logger {
// 	return ctx.Value(loggerCtx{}).(zerolog.Logger)
// }
