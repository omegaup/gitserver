package main

import (
	"encoding/json"
	"io"
)

// DbConfig represents the configuration for the database.
type DbConfig struct {
	Driver         string
	DataSourceName string
}

// LoggingConfig represents the configuration for logging.
type LoggingConfig struct {
	File  string
	Level string
}

// GitserverConfig represents the configuration for the Grader.
type GitserverConfig struct {
	// RootPath is the root path of all repositories.
	RootPath string

	// PublicKey is the base64-encoded public key of the omegaUp frontend.
	// Used for verifying Paseto tokens.
	PublicKey string

	// SecretToken is a shared secret with the frontend that can be used to
	// authenticate instead of using PKI for speeding up tests.
	SecretToken string

	// Port is the TCP port in which the server will listen.
	Port uint16

	// PprofPort is the TCP port in which the pprof server will listen.
	PprofPort uint16

	// LibinteractivePath is the path of libinteractive.jar.
	LibinteractivePath string

	// AllowDirectPushToMaster determines whether gitserver allows pushing
	// directly to master.
	AllowDirectPushToMaster bool

	// FrontendSharedSecret is a secret shared with the frontend to be able to
	// call privileged APIs without needing to authenticate.
	FrontendSharedSecret string

	// FrontendAuthorizationProblemRequestURL is the URL of the frontend API
	// request to get user's privileges for a problem.
	FrontendAuthorizationProblemRequestURL string
}

// Config represents the configuration for the whole program.
type Config struct {
	Db        DbConfig
	Logging   LoggingConfig
	Gitserver GitserverConfig
}

var defaultConfig = Config{
	Db: DbConfig{
		Driver:         "sqlite3",
		DataSourceName: "./omegaup.db",
	},
	Logging: LoggingConfig{
		File:  "/var/log/omegaup/gitserver.log",
		Level: "info",
	},
	Gitserver: GitserverConfig{
		RootPath:                               "/var/lib/omegaup/problems.git",
		PublicKey:                              "gKEg5JlIOA1BsIxETZYhjd+ZGchY/rZeQM0GheAWvXw=",
		SecretToken:                            "",
		Port:                                   33861,
		PprofPort:                              33862,
		LibinteractivePath:                     "/usr/share/java/libinteractive.jar",
		AllowDirectPushToMaster:                false,
		FrontendSharedSecret:                   "secret",
		FrontendAuthorizationProblemRequestURL: "https://omegaup.com/api/authorization/problem/",
	},
}

// DefaultConfig returns a default Config.
func DefaultConfig() Config {
	return defaultConfig
}

// NewConfig creates a new Config from the specified reader.
func NewConfig(reader io.Reader) (*Config, error) {
	config := defaultConfig

	// Read basic config
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return nil, err
	}

	return &config, nil
}
