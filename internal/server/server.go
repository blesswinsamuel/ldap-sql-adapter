package server

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"strings"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/blesswinsamuel/api-forward-auth/internal/cookie"
	"github.com/blesswinsamuel/api-forward-auth/internal/provider"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"

	"github.com/blesswinsamuel/api-forward-auth/internal/config"
)

//go:embed html/*.html
var files embed.FS

// Server contains router and handler methods
type Server struct {
	router        *mux.Router
	logger        zerolog.Logger
	cookieFactory *cookie.CookieFactory
	config        *config.Config
	templates     map[string]*template.Template

	authProvider provider.Provider
}

// NewServer creates a new server object and builds router
func NewServer(cfg *config.Config, authProvider provider.Provider, logger zerolog.Logger) *Server {
	s := &Server{
		router:        mux.NewRouter(),
		authProvider:  authProvider,
		logger:        logger,
		cookieFactory: cookie.NewCookieFactory(cfg),
		config:        cfg,
		templates:     map[string]*template.Template{},
	}
	tmplFiles, err := fs.ReadDir(files, "html")
	if err != nil {
		panic(err)
	}
	for _, tmpl := range tmplFiles {
		if tmpl.IsDir() {
			continue
		}

		if pt, err := template.ParseFS(files, "html/"+tmpl.Name(), "html/layout.html"); err != nil {
			panic(err)
		} else {
			s.templates[tmpl.Name()] = pt
		}
	}

	s.buildRoutes()

	err = s.router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
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

func (s *Server) buildRoutes() {
	s.router.Use(prometheusMiddleware)
	s.router.Use(s.loggerMiddleware)

	s.router.Methods(http.MethodGet).Path("/").Handler(s.HandlerLoginUIGET())
	s.router.Methods(http.MethodGet).Path("/reset-password").Handler(s.HandlerResetPasswordUIGET())

	s.router.Methods(http.MethodGet).Path("/api/verify").Handler(s.HandlerVerifyGET())

	s.router.Methods(http.MethodPost).Path("/api/firstfactor").Handler(s.HandlerFirstFactorPOST())
	s.router.Methods(http.MethodPost).Path("/api/reset-password").Handler(s.HandlerResetPasswordPOST())

	s.router.Methods(http.MethodGet).Path("/logout").Handler(s.HandlerLogoutGet())

	s.router.Handle("/metrics", promhttp.Handler())
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

func (s *Server) checkIsLoggedIn(r *http.Request) (provider.User, error) {
	c, err := r.Cookie(s.config.CookieName)
	if err != nil {
		return nil, NewHttpResponseErrorWithError(err, "Cookie not present", 401)
	}

	// Validate cookie
	userID, err := s.cookieFactory.ValidateCookie(r, c)
	if err != nil {
		if err.Error() == "Cookie has expired" {
			return nil, NewHttpResponseErrorWithError(err, "Cookie has expired", 401)
		}
		return nil, NewHttpResponseErrorWithError(err, "Invalid cookie", 401)
	}

	// Validate user
	userIP := readUserIP(r)
	user, err := s.authProvider.FindByID(r.Context(), userID, userIP)
	if err != nil {
		return nil, NewHttpResponseErrorWithError(fmt.Errorf("couldn't reach DB: %w", err), "Internal Server Error", 500)
	}
	if user == nil {
		return nil, NewHttpResponseErrorWithError(fmt.Errorf("invalid user ID (user who was previously authenticated might have been deleted)"), "Invalid user ID", 401)
	}
	return user, nil
}

func readUserIP(r *http.Request) string {
	ip := r.Header.Get("X-Real-Ip")
	if ip == "" {
		ip = r.Header.Get("X-Forwarded-For")
	}
	if ip == "" {
		ip = r.RemoteAddr
	}
	return ip
}

// HandlerVerifyGET Authenticates requests - this handler is called by traefik to authenticate every request
func (s *Server) HandlerVerifyGET() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := getLogger(r.Context())

		// Get auth cookie
		user, err := s.checkIsLoggedIn(r)
		if err != nil {
			var httpErr *HttpResponseError
			if errors.As(err, &httpErr) {
				if httpErr.statusCode == http.StatusUnauthorized {
					logger.Warn().Err(err).Msg("Unauthorized: redirecting to login")
					redirectURL := s.cookieFactory.RedirectUri(r)
					if r.Header.Get("X-Requested-With") == "ajax" {
						writeJsonResponse(w, struct {
							RedirectTo string `json:"redirect_to"`
							Error      string `json:"error"`
						}{redirectURL, httpErr.message}, httpErr.statusCode)
					} else {
						http.Redirect(w, r, s.config.PublicURL+"?rd="+redirectURL, http.StatusTemporaryRedirect)
					}
					return
				}
				logger.Warn().Err(err).Msg(httpErr.message)
				writeErrorResponse(w, httpErr.message, httpErr.statusCode)
				return
			} else {
				logger.Error().Err(err).Msg("Unknown error")
				writeErrorResponse(w, "Internal Server Error", 500)
				return
			}
		}

		// Valid request
		logger.Debug().Msg("Allowing valid request")
		w.Header().Set("Remote-User", fmt.Sprint(user["id"]))
		w.Header().Set("Remote-Name", fmt.Sprint(user["username"]))
		w.Header().Set("Remote-Permissions", fmt.Sprint(user["permissions"]))
		w.WriteHeader(200)
	}
}

func (s *Server) HandlerResetPasswordPOST() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := getLogger(r.Context())

		var resetPasswordReq struct {
			Email    string `json:"email"`
			Token    string `json:"token"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&resetPasswordReq); err != nil {
			logger.Warn().Err(err).Msg("Bad auth request")
			writeErrorResponse(w, "Bad request", 400)
			return
		}

		if resetPasswordReq.Email != "" && resetPasswordReq.Token == "" && resetPasswordReq.Password == "" {
			// initiate password reset
			err := s.authProvider.ResetPasswordInitiate(r.Context(), resetPasswordReq.Email)
			if err != nil {
				handleUpstreamHTTPError(w, err, logger, "Failed to initiate password reset")
				return
			}
			writeJsonResponse(w, struct{}{}, 200)
			return
		}
		if resetPasswordReq.Email != "" && resetPasswordReq.Token != "" && resetPasswordReq.Password != "" {
			// reset password
			err := s.authProvider.ResetPassword(r.Context(), resetPasswordReq.Email, resetPasswordReq.Token, resetPasswordReq.Password)
			if err != nil {
				handleUpstreamHTTPError(w, err, logger, "Failed to reset password")
				return
			}
			writeJsonResponse(w, struct{}{}, 200)
			return
		}
		writeErrorResponse(w, "Bad request", 400)
	}
}

// HandlerFirstFactorPOST Handles auth callback request
func (s *Server) HandlerFirstFactorPOST() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := getLogger(r.Context())

		var userReq struct {
			Username  string `json:"username"`
			Password  string `json:"password"`
			State     string `json:"state"`
			TargetURL string `json:"target_url"`
		}
		if err := json.NewDecoder(r.Body).Decode(&userReq); err != nil {
			logger.Warn().Err(err).Msg("Bad auth request")
			writeErrorResponse(w, "Bad request", 400)
			return
		}

		// Get user
		user, err := s.authProvider.Authenticate(r.Context(), userReq.Username, userReq.Password)
		if err != nil {
			handleUpstreamHTTPError(w, err, logger, "Failed to authenticate user")
			return
		}

		redirect := userReq.TargetURL
		if redirect == "" {
			redirect = "" // default redirect url
		}

		// Generate cookie
		http.SetCookie(w, s.cookieFactory.MakeCookie(r, fmt.Sprint(user["id"])))
		logger.Info().Str("redirect", redirect).Interface("user", user).Msg("Successfully generated auth cookie, redirecting user.")

		// Redirect
		writeJsonResponse(w, struct {
			RedirectTo string `json:"redirect_to"`
		}{redirect}, http.StatusOK)
	}
}

// HandlerLogoutGet logs a user out
func (s *Server) HandlerLogoutGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Clear cookie
		http.SetCookie(w, s.cookieFactory.ClearCookie(r))

		if rd := r.URL.Query().Get("rd"); rd != "" {
			http.Redirect(w, r, rd, http.StatusTemporaryRedirect)
			return
		}

		if s.config.LogoutRedirect != "" {
			http.Redirect(w, r, s.config.LogoutRedirect, http.StatusTemporaryRedirect)
		} else {
			http.Error(w, "You have been logged out", http.StatusUnauthorized)
		}
	}
}

// HandlerResetPasswordUIGET shows reset password ui
func (s *Server) HandlerResetPasswordUIGET() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		email, token := r.URL.Query().Get("email"), r.URL.Query().Get("token")
		if email == "" || token == "" {
			if err := s.templates["reset-password-initiate.html"].Execute(w, map[string]interface{}{
				"LogoURL": template.URL(s.config.LogoURL),
			}); err != nil {
				s.logger.Error().Err(err).Msgf("resetPasswordTemplate.Execute: %v", err)
				return
			}
		} else {
			if err := s.templates["reset-password.html"].Execute(w, map[string]interface{}{
				"LogoURL": template.URL(s.config.LogoURL),
				"Email":   email,
				"Token":   token,
			}); err != nil {
				s.logger.Error().Err(err).Msgf("resetPasswordTemplate.Execute: %v", err)
				return
			}
		}
	}
}

// HandlerLoginUIGET shows login ui
func (s *Server) HandlerLoginUIGET() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := getLogger(r.Context())

		user, err := s.checkIsLoggedIn(r)
		if err != nil {
			httpErr := &HttpResponseError{}
			if errors.As(err, &httpErr) {
				if httpErr.statusCode != http.StatusUnauthorized {
					logger.Warn().Err(err).Msg(httpErr.message)
					writeErrorResponse(w, httpErr.message, httpErr.statusCode)
					return
				}
			} else {
				logger.Warn().Err(err).Msg("Unknown error")
				writeErrorResponse(w, "Internal Server Error", 500)
				return
			}
		}
		if user != nil {
			if err := s.templates["logged-in.html"].Execute(w, map[string]interface{}{
				"Name":    user["username"],
				"LogoURL": template.URL(s.config.LogoURL),
			}); err != nil {
				logger.Error().Err(err).Msgf("loggedInTemplate.Execute: %v", err)
				return
			}
			return
		}

		if !s.config.InsecureCookie && r.Header.Get("X-Forwarded-Proto") != "https" {
			logger.Warn().Msg("You are using \"secure\" cookies for a request that was not " +
				"received via https. You should either redirect to https or pass the " +
				"\"insecure-cookie\" config option to permit cookies via http.")
		}

		// Unauthorized - display login page
		if err := s.templates["login.html"].Execute(w, map[string]interface{}{
			"LogoURL": template.URL(s.config.LogoURL),
		}); err != nil {
			logger.Error().Err(err).Msgf("loginTemplate.Execute: %v", err)
			return
		}
	}
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
		s.logger.Debug().Interface("cookies", r.Cookies()).Msg("Received request")

		r = r.WithContext(context.WithValue(r.Context(), loggerCtx{}, logger))

		h.ServeHTTP(w, r)
	})
}

type loggerCtx struct{}

func getLogger(ctx context.Context) zerolog.Logger {
	return ctx.Value(loggerCtx{}).(zerolog.Logger)
}
