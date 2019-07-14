package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/inconshreveable/log15"
	"github.com/o1egl/paseto"
	"github.com/omegaup/githttp"
	"github.com/omegaup/gitserver/request"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ed25519"
	"net/http"
	"strings"
	"time"
)

const (
	basicAuthenticationScheme               = "Basic"
	bearerAuthenticationScheme              = "Bearer"
	omegaUpSharedSecretAuthenticationScheme = "OmegaUpSharedSecret"
)

type omegaupAuthorization struct {
	log         log15.Logger
	publicKey   ed25519.PublicKey
	secretToken string
}

func (a *omegaupAuthorization) parseBearerToken(token string) (username, problem string, ok bool) {
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

	if a.secretToken != "" && password == a.secretToken {
		username = basicAuthUsername
		problem = repositoryName
		ok = true
	}

	return
}

func (a *omegaupAuthorization) parseAuthorizationHeader(
	authorizationHeader string,
	repositoryName string,
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

	if a.secretToken != "" {
		if strings.EqualFold(tokens[0], omegaUpSharedSecretAuthenticationScheme) {
			if len(tokens) != 3 {
				return
			}

			if tokens[1] != a.secretToken {
				return
			}

			username = tokens[2]
			problem = repositoryName
			ok = true
		}
	}

	return
}

func (a *omegaupAuthorization) authorize(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	repositoryName string,
	operation githttp.GitOperation,
) (githttp.AuthorizationLevel, string) {
	basicAuthUsername, password, ok := r.BasicAuth()
	var username, problem string
	if ok {
		username, problem, ok = a.parseUsernameAndPassword(basicAuthUsername, password, repositoryName)
	}
	if !ok {
		username, problem, ok = a.parseAuthorizationHeader(r.Header.Get("Authorization"), repositoryName)
	}

	if basicAuthUsername != "" && basicAuthUsername != username {
		// If Basic authentication was attempted, verify that the token actually corresponds to the user.
		ok = false
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
		if a.secretToken != "" {
			authenticationSchemes = append(
				authenticationSchemes,
				fmt.Sprintf("%s realm=%q", omegaUpSharedSecretAuthenticationScheme, realm),
			)
		}
		w.Header().Set("WWW-Authenticate", strings.Join(authenticationSchemes, ", "))
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
	auth := omegaupAuthorization{
		log: log,
	}

	if config.Gitserver.SecretToken != "" {
		log.Warn("using insecure secret token authorization")
		auth.secretToken = config.Gitserver.SecretToken
	}
	if config.Gitserver.PublicKey != "" {
		keyBytes, err := base64.StdEncoding.DecodeString(config.Gitserver.PublicKey)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse the base64-encoded public key")
		}

		auth.publicKey = ed25519.PublicKey(keyBytes)
	}
	return auth.authorize, nil
}
