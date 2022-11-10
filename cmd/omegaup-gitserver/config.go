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
	JSON  bool
}

// NewRelicConfig represents the configuration for NewRelic.
type NewRelicConfig struct {
	AppName string
	License string
}

// GitserverConfig represents the configuration for the Grader.
type GitserverConfig struct {
	// RootPath is the root path of all repositories.
	RootPath string

	// PublicKey is the base64-encoded public key of the omegaUp frontend.
	// Used for verifying Paseto tokens.
	PublicKey string

	// SecretToken is a shared secret with the frontend that can be used to
	// authenticate instead of using PKI, in both directions.
	SecretToken string

	// GraderSecretToken is a shared secret with the grader that can be used to
	// authenticate instead of using PKI, in both directions.
	GraderSecretToken string

	// AllowSecretTokenAuthentication controls whether the SecretToken can be
	// used to authenticate incoming requests, instead of just being used for
	// outgoing requests towards the frontend.
	AllowSecretTokenAuthentication bool

	// Port is the TCP port in which the server will listen.
	Port uint16

	// PprofPort is the TCP port in which the pprof server will listen.
	PprofPort uint16

	// LibinteractivePath is the path of libinteractive.jar.
	LibinteractivePath string

	// AllowDirectPushToMaster determines whether gitserver allows pushing
	// directly to master.
	AllowDirectPushToMaster bool

	// FrontendAuthorizationProblemRequestURL is the URL of the frontend API
	// request to get user's privileges for a problem.
	FrontendAuthorizationProblemRequestURL string

	// UseS3 determines whether gitserver will push to / pull from S3.
	UseS3 bool
}

// Config represents the configuration for the whole program.
type Config struct {
	Db        DbConfig
	Logging   LoggingConfig
	NewRelic  NewRelicConfig
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
	NewRelic: NewRelicConfig{
		AppName: "gitserver.omegaup.com",
	},
	Gitserver: GitserverConfig{
		RootPath:                               "/var/lib/omegaup/problems.git",
		PublicKey:                              "gKEg5JlIOA1BsIxETZYhjd+ZGchY/rZeQM0GheAWvXw=",
		SecretToken:                            "",
		GraderSecretToken:                      "",
		Port:                                   33861,
		PprofPort:                              33862,
		LibinteractivePath:                     "/usr/share/java/libinteractive.jar",
		AllowDirectPushToMaster:                false,
		FrontendAuthorizationProblemRequestURL: "https://omegaup.com/api/authorization/problem/",
		UseS3:                                  false,
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
