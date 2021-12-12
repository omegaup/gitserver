package main

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/omegaup/githttp/v2"
	"github.com/omegaup/gitserver/request"
	"github.com/omegaup/go-base/v3/logging"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/mattn/go-sqlite3"
	"github.com/newrelic/go-agent/v3/newrelic"
	"github.com/o1egl/paseto"
	"github.com/pkg/errors"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/ed25519"
)

var (
	// ErrInvalidHash is returned if the hash is not in the correct format.
	ErrInvalidHash = stderrors.New("the encoded hash is not in the correct format")
	// ErrIncompatibleVersion is returned if the version of the hash is not 19.
	ErrIncompatibleVersion = stderrors.New("incompatible version of argon2")
)

const (
	basicAuthenticationScheme               = "Basic"
	bearerAuthenticationScheme              = "Bearer"
	omegaUpSharedSecretAuthenticationScheme = "OmegaUpSharedSecret"
)

type omegaupAuthorization struct {
	log       logging.Logger
	db        *sql.DB
	publicKey ed25519.PublicKey

	config *Config
}

type authorizationProblemResponse struct {
	Status    string `json:"status"`
	HasSolved bool   `json:"has_solved"`
	IsSystem  bool   `json:"is_system"`
	IsAdmin   bool   `json:"is_admin"`
	CanView   bool   `json:"can_view"`
	CanEdit   bool   `json:"can_edit"`
}

func verifyArgon2idHash(password, encodedHash string) (bool, error) {
	tokens := strings.Split(encodedHash, "$")
	if len(tokens) != 6 || tokens[0] != "" || tokens[1] != "argon2id" {
		return false, ErrInvalidHash
	}

	var version int
	if _, err := fmt.Sscanf(tokens[2], "v=%d", &version); err != nil {
		return false, errors.Wrap(err, "failed to parse version")
	}
	if version != argon2.Version {
		return false, ErrIncompatibleVersion
	}

	var memory uint32
	var iterations uint32
	var parallelism uint8
	if _, err := fmt.Sscanf(tokens[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); err != nil {
		return false, errors.Wrap(err, "failed to parse hash parameters")
	}

	salt, err := base64.RawStdEncoding.DecodeString(tokens[4])
	if err != nil {
		return false, errors.Wrap(err, "failed to decode salt")
	}

	hash, err := base64.RawStdEncoding.DecodeString(tokens[5])
	if err != nil {
		return false, errors.Wrap(err, "failed to decode hash")
	}

	otherHash := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, uint32(len(hash)))
	return subtle.ConstantTimeCompare(hash, otherHash) == 1, nil
}

func (a *omegaupAuthorization) parseBearerToken(token string) (username, problem string, ok bool) {
	var jsonToken paseto.JSONToken
	var footer string
	if err := paseto.NewV2().Verify(token, a.publicKey, &jsonToken, &footer); err != nil {
		a.log.Error(
			"failed to verify token",
			map[string]interface{}{
				"err": err,
			},
		)
		return
	}

	if err := jsonToken.Validate(paseto.IssuedBy("omegaUp frontend"), paseto.ValidAt(time.Now())); err != nil {
		a.log.Error(
			"failed to validate token",
			map[string]interface{}{
				"err": err,
			},
		)
		return
	}

	username = jsonToken.Subject
	problem = jsonToken.Get("problem")
	ok = true
	return
}

func (a *omegaupAuthorization) parseUsernameAndPassword(
	basicAuthUsername string,
	password string,
	repositoryName string,
) (username, problem string, ok bool) {
	if a.publicKey != nil && strings.HasPrefix(password, "v2.public.") {
		username, problem, ok = a.parseBearerToken(password)
		if ok {
			return
		}
	}

	if a.config.Gitserver.AllowSecretTokenAuthentication &&
		a.config.Gitserver.SecretToken != "" &&
		password == a.config.Gitserver.SecretToken {
		username = basicAuthUsername
		problem = repositoryName
		ok = true
		return
	}

	if username == "omegaup:system" {
		// omegaup:system can only log in using the auth token or the secret token.
		a.log.Error(
			"user tried to login with restricted user",
			map[string]interface{}{
				"username": username,
			},
		)
		return
	}

	var gitToken sql.NullString
	err := a.db.QueryRow(
		`SELECT
			u.git_token
		FROM
			Users u
		INNER JOIN
			Identities i ON i.identity_id = u.main_identity_id
		WHERE
			i.username = ?;`,
		basicAuthUsername,
	).Scan(
		&gitToken,
	)
	if err != nil {
		a.log.Error(
			"failed to query user",
			map[string]interface{}{
				"username": username,
				"err":      err,
			},
		)
		return
	}

	if !gitToken.Valid {
		a.log.Error(
			"user is missing a git token",
			map[string]interface{}{
				"username": username,
			},
		)
		return
	}

	ok, err = verifyArgon2idHash(password, gitToken.String)
	if err != nil {
		a.log.Error(
			"failed to verify user's git token",
			map[string]interface{}{
				"username": username,
				"err":      err,
			},
		)
		return
	}

	if ok {
		username = basicAuthUsername
		problem = repositoryName
	} else {
		a.log.Error(
			"user provided the wrong git token",
			map[string]interface{}{
				"username": username,
			},
		)
	}
	return
}

func (a *omegaupAuthorization) parseAuthorizationHeader(
	authorizationHeader string,
	repositoryName string,
	isLocalRequest bool,
) (username, problem string, ok bool) {
	tokens := strings.SplitN(authorizationHeader, " ", 3)

	if a.publicKey != nil {
		if strings.EqualFold(tokens[0], bearerAuthenticationScheme) {
			if len(tokens) != 2 {
				return
			}

			return a.parseBearerToken(tokens[1])
		}
	}

	if a.config.Gitserver.AllowSecretTokenAuthentication && a.config.Gitserver.SecretToken != "" {
		if strings.EqualFold(tokens[0], omegaUpSharedSecretAuthenticationScheme) {
			if len(tokens) != 3 {
				return
			}

			if tokens[1] != a.config.Gitserver.SecretToken {
				return
			}

			username = tokens[2]
			problem = repositoryName
			ok = true
		}
	}

	if isLocalRequest && len(tokens) == 1 && tokens[0] == "omegaup:health" {
		username = tokens[0]
		problem = repositoryName
		ok = true
	}

	return
}

func (a *omegaupAuthorization) getAuthorizationFromFrontend(
	username string,
	problem string,
) (*authorizationProblemResponse, error) {
	client := http.Client{}
	response, err := client.PostForm(
		a.config.Gitserver.FrontendAuthorizationProblemRequestURL,
		url.Values{
			"token":         {a.config.Gitserver.SecretToken},
			"username":      {username},
			"problem_alias": {problem},
		},
	)
	if err != nil {
		return nil, errors.Wrap(
			err,
			"failed to request permissions from the frontend",
		)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		responseBody, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return nil, errors.Wrap(
				errors.Wrap(
					err,
					"failed to read response from server",
				),
				"failed to request permissions from the frontend",
			)
		}
		return nil, errors.Errorf(
			"failed to request permissions from the frontend: %q",
			responseBody,
		)
	}

	var msg authorizationProblemResponse
	decoder := json.NewDecoder(response.Body)
	if err := decoder.Decode(&msg); err != nil {
		return nil, errors.Wrap(
			err,
			"failed to read response for permissions request from the frontend",
		)
	}

	return &msg, nil
}

func (a *omegaupAuthorization) authorize(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	repositoryName string,
	operation githttp.GitOperation,
) (githttp.AuthorizationLevel, string) {
	isLocalRequest := strings.HasPrefix(r.RemoteAddr, "127.0.0.1:")
	basicAuthUsername, password, ok := r.BasicAuth()
	var username, problem string
	if ok {
		username, problem, ok = a.parseUsernameAndPassword(basicAuthUsername, password, repositoryName)
	}
	if !ok {
		username, problem, ok = a.parseAuthorizationHeader(r.Header.Get("Authorization"), repositoryName, isLocalRequest)
	}

	txn := newrelic.FromContext(r.Context())
	txn.AddAttribute("problem", problem)
	txn.AddAttribute("username", username)

	if basicAuthUsername != "" && basicAuthUsername != username {
		// If Basic authentication was attempted, verify that the token actually corresponds to the user.
		ok = false
		a.log.Error(
			"Mismatched Basic authentication username",
			map[string]interface{}{
				"username":            username,
				"basic auth username": basicAuthUsername,
				"repository":          repositoryName,
			},
		)
	}
	if !ok {
		realm := fmt.Sprintf("omegaUp gitserver problem %q", repositoryName)
		authenticationSchemes := []string{
			fmt.Sprintf("%s realm=%q", basicAuthenticationScheme, realm),
		}
		if a.publicKey != nil {
			authenticationSchemes = append(
				authenticationSchemes,
				fmt.Sprintf("%s realm=%q", bearerAuthenticationScheme, realm),
			)
		}
		if a.config.Gitserver.AllowSecretTokenAuthentication && a.config.Gitserver.SecretToken != "" {
			authenticationSchemes = append(
				authenticationSchemes,
				fmt.Sprintf("%s realm=%q", omegaUpSharedSecretAuthenticationScheme, realm),
			)
		}
		w.Header().Set("WWW-Authenticate", strings.Join(authenticationSchemes, ", "))
		w.WriteHeader(http.StatusUnauthorized)
		a.log.Error(
			"Missing authentication",
			map[string]interface{}{
				"username":   username,
				"repository": repositoryName,
			},
		)
		return githttp.AuthorizationDenied, ""
	}

	if problem != repositoryName {
		w.WriteHeader(http.StatusForbidden)
		a.log.Error(
			"Mismatched problem name",
			map[string]interface{}{
				"username":   username,
				"repository": repositoryName,
				"problem":    problem,
			},
		)
		return githttp.AuthorizationDenied, ""
	}

	requestContext := request.FromContext(ctx)
	requestContext.Request.ProblemName = problem
	requestContext.Request.Username = username
	if username == "omegaup:health" && requestContext.Request.ProblemName == ":testproblem" && isLocalRequest {
		// This is a legit health check, so we grant privileges to the test problem.
		requestContext.Request.CanView = true
		requestContext.Request.CanEdit = true
	} else if username == "omegaup:system" || *insecureSkipAuthorization {
		// This is the frontend, and we trust it completely.
		requestContext.Request.IsSystem = true
		requestContext.Request.IsAdmin = true
		requestContext.Request.CanView = true
		requestContext.Request.CanEdit = true
	} else if requestContext.Request.Create {
		// This is a repository creation request. There is nothing in the database
		// yet, so grant them all privileges.
		requestContext.Request.IsAdmin = true
		requestContext.Request.CanView = true
		requestContext.Request.CanEdit = true
	} else {
		auth, err := a.getAuthorizationFromFrontend(
			username,
			problem,
		)
		if err != nil {
			a.log.Error(
				"Auth",
				map[string]interface{}{
					"username":   username,
					"repository": repositoryName,
					"operation":  operation,
					"err":        err,
				},
			)
			return githttp.AuthorizationDenied, username
		}
		requestContext.Request.HasSolved = auth.HasSolved
		requestContext.Request.IsAdmin = auth.IsAdmin
		requestContext.Request.CanView = auth.CanView
		requestContext.Request.CanEdit = auth.CanEdit
	}
	a.log.Info(
		"Auth",
		map[string]interface{}{
			"username":   username,
			"repository": repositoryName,
			"operation":  operation,
		},
	)
	return githttp.AuthorizationAllowed, username
}

func createAuthorizationCallback(config *Config, log logging.Logger) (githttp.AuthorizationCallback, error) {
	auth := omegaupAuthorization{
		log:    log,
		config: config,
	}

	if config.Gitserver.AllowSecretTokenAuthentication {
		log.Warn("using insecure secret token authorization", nil)
	}
	if config.Gitserver.PublicKey != "" {
		keyBytes, err := base64.StdEncoding.DecodeString(config.Gitserver.PublicKey)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse the base64-encoded public key")
		}

		auth.publicKey = ed25519.PublicKey(keyBytes)
	}

	db, err := sql.Open(
		config.Db.Driver,
		config.Db.DataSourceName,
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to open the database")
	}
	if err := db.Ping(); err != nil {
		return nil, errors.Wrap(err, "failed to ping the database")
	}
	auth.db = db
	return auth.authorize, nil
}
