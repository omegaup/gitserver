package main

import (
	"context"
	"encoding/base64"
	"github.com/inconshreveable/log15"
	"github.com/o1egl/paseto"
	"github.com/omegaup/githttp"
	"github.com/omegaup/gitserver/request"
	errors "github.com/pkg/errors"
	"golang.org/x/crypto/ed25519"
	"net/http"
	"strings"
	"time"
)

type bearerAuthorization struct {
	log       log15.Logger
	publicKey ed25519.PublicKey
}

func (a *bearerAuthorization) parseBearerToken(token string) (username, problem string, ok bool) {
	var jsonToken paseto.JSONToken
	var footer string
	if err := paseto.NewV2().Verify(token, a.publicKey, &jsonToken, &footer); err != nil {
		a.log.Error("failed to verify token", "err", err)
		return
	}

	if err := jsonToken.Validate(paseto.IssuedBy("omegaUp frontend"), paseto.ValidAt(time.Now())); err != nil {
		a.log.Error("failed to validate token", "err", err)
		return
	}

	username = jsonToken.Subject
	problem = jsonToken.Get("problem")
	ok = true
	return
}

func (a *bearerAuthorization) extractBearerToken(auth string) (token string, ok bool) {
	const prefix = "Bearer "
	// Case insensitive prefix match. See Issue 22736.
	if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return "", false
	}

	return auth[len(prefix):], true
}

func (a *bearerAuthorization) authorize(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	repositoryName string,
	operation githttp.GitOperation,
) (githttp.AuthorizationLevel, string) {
	basicAuthUsername, token, ok := r.BasicAuth()
	if !ok {
		token, ok = a.extractBearerToken(r.Header.Get("Authorization"))
	}
	var username, problem string
	if ok {
		username, problem, ok = a.parseBearerToken(token)
	}
	if basicAuthUsername != "" && basicAuthUsername != username {
		// If Basic authentication was attempted, verify that the token actually corresponds to the user.
		ok = false
	}
	if !ok {
		w.Header().Set(
			"WWW-Authenticate",
			"Basic realm=\"omegaUp gitserver\", Bearer realm=\"omegaUp gitserver\"",
		)
		w.WriteHeader(http.StatusUnauthorized)
		return githttp.AuthorizationDenied, ""
	}

	if problem != repositoryName {
		w.WriteHeader(http.StatusForbidden)
		return githttp.AuthorizationDenied, ""
	}

	log.Info(
		"Auth",
		"username", username,
		"problem", problem,
		"repository", repositoryName,
		"operation", operation,
	)
	requestContext := request.FromContext(ctx)
	// Right now only the frontend can issue requests, so we trust it completely.
	requestContext.CanView = true
	requestContext.IsAdmin = true
	requestContext.CanEdit = true
	return githttp.AuthorizationAllowed, username
}

type secretTokenAuthorization struct {
	log         log15.Logger
	secretToken string
}

func (a *secretTokenAuthorization) parseSecretTokenAuth(auth string) (username string, ok bool) {
	tokens := strings.SplitN(auth, " ", 3)
	if len(tokens) != 3 {
		return
	}

	if !strings.EqualFold(tokens[0], "Bearer") {
		return
	}
	if tokens[1] != a.secretToken {
		return
	}

	username = tokens[2]
	ok = true
	return
}

func (a *secretTokenAuthorization) authorize(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	repositoryName string,
	operation githttp.GitOperation,
) (githttp.AuthorizationLevel, string) {
	username, password, ok := r.BasicAuth()
	if !ok || !strings.EqualFold(password, a.secretToken) {
		username, ok = a.parseSecretTokenAuth(r.Header.Get("Authorization"))
	}
	if !ok {
		w.Header().Set(
			"WWW-Authenticate",
			"Basic realm=\"omegaUp gitserver\", Bearer realm=\"omegaUp gitserver\"",
		)
		w.WriteHeader(http.StatusUnauthorized)
		return githttp.AuthorizationDenied, ""
	}

	log.Info(
		"Auth",
		"username", username,
		"repository", repositoryName,
		"operation", operation,
	)
	requestContext := request.FromContext(ctx)
	// Right now only the frontend can issue requests, so we trust it completely.
	requestContext.CanView = true
	requestContext.IsAdmin = true
	requestContext.CanEdit = true
	return githttp.AuthorizationAllowed, username
}

func createAuthorizationCallback(config *Config, log log15.Logger) (githttp.AuthorizationCallback, error) {
	if config.Gitserver.PublicKeyBase64 == "" && config.Gitserver.SecretToken != "" {
		log.Warn("using insecure secret token authorization")
		auth := secretTokenAuthorization{
			log:         log,
			secretToken: config.Gitserver.SecretToken,
		}
		return auth.authorize, nil
	}
	keyBytes, err := base64.StdEncoding.DecodeString(config.Gitserver.PublicKeyBase64)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse the base64-encoded public key")
	}

	auth := bearerAuthorization{
		log:       log,
		publicKey: ed25519.PublicKey(keyBytes),
	}
	return auth.authorize, nil
}
