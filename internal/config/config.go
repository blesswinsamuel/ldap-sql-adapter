package config

import (
	"encoding/json"
	"log"
	"os"
	"time"

	"github.com/jessevdk/go-flags"
	"github.com/joho/godotenv"
)

// Config holds the runtime application config
type Config struct {
	Env string `long:"env" env:"GO_ENV" default:"development"`

	LogLevel string `long:"log-level" env:"LOG_LEVEL" default:"info" choice:"trace" choice:"debug" choice:"info" choice:"warn" choice:"error" choice:"fatal" choice:"panic" description:"Log level"`

	Config         func(s string) error `long:"config" env:"CONFIG" description:"Path to config file" json:"-"`
	ApiURL         string               `long:"api-url" env:"API_URL" description:"API URL"`
	LogoURL        string               `long:"logo-url" env:"LOGO_URL" description:"Logo URL"`
	PublicURL      string               `long:"public-url" env:"PUBLIC_URL" description:"Public URL"`
	CookieDomains  []string             `long:"cookie-domain" env:"COOKIE_DOMAIN" env-delim:"," description:"Domain to set auth cookie on, can be set multiple times"`
	InsecureCookie bool                 `long:"insecure-cookie" env:"INSECURE_COOKIE" description:"Use insecure cookies"`
	CookieName     string               `long:"cookie-name" env:"COOKIE_NAME" default:"_forward_auth" description:"Cookie Name"`
	Lifetime       time.Duration        `long:"lifetime" env:"LIFETIME" default:"12h" description:"Lifetime in seconds"`
	LogoutRedirect string               `long:"logout-redirect" env:"LOGOUT_REDIRECT" default:"/" description:"URL to redirect to following logout"`
	SecretString   string               `long:"secret" env:"SECRET" description:"Secret used for signing (required)" json:"-"`
	Host           string               `long:"host" env:"HOST" default:"localhost" description:"Host to listen on"`
	Port           int                  `long:"port" env:"PORT" default:"4181" description:"Port to listen on"`

	DatabaseURL string `long:"database-url" env:"DATABASE_URL"`

	// Filled during transformations
	Secret []byte `json:"-"`
}

// ParseConfig parses and validates provided configuration into a config object
func ParseConfig(args []string) (*Config, error) {
	if args == nil {
		args = os.Args[1:]
	}
	var config = new(Config)
	config.Env = os.Getenv("GO_ENV")
	if config.Env == "" {
		config.Env = "development"
	}

	_ = godotenv.Load(".env." + config.Env + ".local")
	if config.Env != "test" {
		_ = godotenv.Load(".env.local")
	}
	_ = godotenv.Load(".env." + config.Env)
	_ = godotenv.Load() // The Original .env

	c := &Config{}

	err := c.parseFlags(args)
	if err != nil {
		return c, err
	}

	// Transformations
	c.Secret = []byte(c.SecretString)
	if c.LogoURL == "" {
		c.LogoURL = `data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxNiIgaGVpZ2h0PSIxNiIgZmlsbD0iY3VycmVudENvbG9yIiBjbGFzcz0iYmkgYmktbG9jayIgdmlld0JveD0iMCAwIDE2IDE2Ij4KICA8cGF0aCBkPSJNOCAxYTIgMiAwIDAgMSAyIDJ2NEg2VjNhMiAyIDAgMCAxIDItMnptMyA2VjNhMyAzIDAgMCAwLTYgMHY0YTIgMiAwIDAgMC0yIDJ2NWEyIDIgMCAwIDAgMiAyaDZhMiAyIDAgMCAwIDItMlY5YTIgMiAwIDAgMC0yLTJ6TTUgOGg2YTEgMSAwIDAgMSAxIDF2NWExIDEgMCAwIDEtMSAxSDVhMSAxIDAgMCAxLTEtMVY5YTEgMSAwIDAgMSAxLTF6Ii8+Cjwvc3ZnPg==`
	}

	return c, nil
}

func (c *Config) parseFlags(args []string) error {
	p := flags.NewParser(c, flags.Default)

	i := flags.NewIniParser(p)
	c.Config = func(s string) error {
		return i.ParseFile(s)
	}

	_, err := p.ParseArgs(args)
	if err != nil {
		return handleFlagError(err)
	}

	return nil
}

func handleFlagError(err error) error {
	flagsErr, ok := err.(*flags.Error)
	if ok && flagsErr.Type == flags.ErrHelp {
		// Library has just printed cli help
		os.Exit(0)
	}

	return err
}

// Validate validates a config object
func (c *Config) Validate() {
	// Check for show stopper errors
	if len(c.Secret) == 0 {
		log.Fatal("\"secret\" option must be set")
	}
}

func (c Config) String() string {
	jsonConf, _ := json.Marshal(c)
	return string(jsonConf)
}
