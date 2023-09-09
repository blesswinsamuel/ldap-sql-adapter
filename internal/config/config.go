package config

import (
	"encoding/json"
	"os"

	"github.com/blesswinsamuel/ldap-sql-proxy/internal/provider"
	"github.com/jessevdk/go-flags"
	"github.com/joho/godotenv"
)

// Config holds the runtime application config
type Config struct {
	Env string `long:"env" env:"GO_ENV" default:"development"`

	LogLevel string `long:"log-level" env:"LOG_LEVEL" default:"info" choice:"trace" choice:"debug" choice:"info" choice:"warn" choice:"error" choice:"fatal" choice:"panic" description:"Log level"`

	Config   func(s string) error `long:"config" env:"CONFIG" description:"Path to config file" json:"-"`
	Host     string               `long:"host" env:"HOST" default:"localhost" description:"Host to listen on"`
	HttpPort int                  `long:"http-port" env:"HTTP_PORT" default:"4181" description:"Metrics port to listen on"`
	LdapPort int                  `long:"ldap-port" env:"LDAP_PORT" default:"10389" description:"Ldap port to listen on"`

	BindUsername string `long:"bind-username" env:"BIND_USERNAME" default:"admin"`
	BindPassword string `long:"bind-password" env:"BIND_PASSWORD" default:"admin"`
	BaseDN       string `long:"base-dn" env:"BASE_DN" default:"dc=example,dc=com"`

	provider.SQLProviderConfig

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

	c.BindUsername = "cn=" + c.BindUsername + "," + c.BaseDN

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
}

func (c Config) String() string {
	jsonConf, _ := json.Marshal(c)
	return string(jsonConf)
}
