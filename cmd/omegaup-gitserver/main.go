package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"github.com/coreos/go-systemd/daemon"
	"github.com/inconshreveable/log15"
	git "github.com/lhchavez/git2go"
	"github.com/o1egl/paseto"
	"github.com/omegaup/githttp"
	"github.com/omegaup/gitserver"
	"github.com/omegaup/gitserver/request"
	base "github.com/omegaup/go-base"
	"golang.org/x/crypto/ed25519"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	configPath = flag.String(
		"config",
		"/etc/omegaup/gitserver/config.json",
		"gitserver configuration file",
	)
	version = flag.Bool("version", false, "Print the version and exit")
	log     log15.Logger

	// ProgramVersion is the version of the code from which the binary was built from.
	ProgramVersion string
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

func referenceDiscovery(
	ctx context.Context,
	repository *git.Repository,
	referenceName string,
) bool {
	requestContext := request.FromContext(ctx)
	if requestContext.CanEdit {
		return true
	}
	if requestContext.HasSolved {
		return referenceName == "refs/heads/public" ||
			referenceName == "refs/heads/protected" ||
			referenceName == "refs/heads/private"
	}

	return referenceName == "refs/heads/public"
}

type muxGitHandler struct {
	log            log15.Logger
	gitHandler     http.Handler
	zipHandler     http.Handler
	metricsHandler http.Handler
}

func muxHandler(
	rootPath string,
	protocol *githttp.GitProtocol,
	log log15.Logger,
) http.Handler {
	metrics, metricsHandler := gitserver.SetupMetrics()
	return &muxGitHandler{
		log:            log,
		gitHandler:     gitserver.GitHandler(rootPath, protocol, metrics, log),
		zipHandler:     gitserver.ZipHandler(rootPath, protocol, metrics, log),
		metricsHandler: metricsHandler,
	}
}

func (h *muxGitHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	splitPath := strings.SplitN(r.URL.Path[1:], "/", 2)
	if len(splitPath) >= 1 && splitPath[0] == "metrics" {
		h.metricsHandler.ServeHTTP(w, r)
	} else if len(splitPath) == 2 && splitPath[1] == "git-upload-zip" {
		h.zipHandler.ServeHTTP(w, r)
	} else {
		h.gitHandler.ServeHTTP(w, r)
	}
}

func main() {
	defer git.Shutdown()

	flag.Parse()

	if *version {
		fmt.Printf("omegaup-gitserver %s\n", ProgramVersion)
		return
	}

	f, err := os.Open(*configPath)
	if err != nil {
		panic(err)
	}
	config, err := NewConfig(f)
	if err != nil {
		panic(err)
	}
	f.Close()

	if config.Logging.File != "" {
		var err error
		if log, err = base.RotatingLog(config.Logging.File, config.Logging.Level); err != nil {
			panic(err)
		}
	} else if config.Logging.Level == "debug" {
		log = base.StderrLog()
	} else {
		log = log15.New()
		log.SetHandler(base.ErrorCallerStackHandler(log15.LvlInfo, log15.StderrHandler))
	}

	if config.Gitserver.RootPath == "" {
		log.Error("root path cannot be empty. Please specify one with -root")
		os.Exit(1)
	}

	stopChan := make(chan os.Signal)
	signal.Notify(stopChan, syscall.SIGINT, syscall.SIGTERM)

	var authCallback githttp.AuthorizationCallback
	if config.Gitserver.PublicKeyBase64 == "" && config.Gitserver.SecretToken != "" {
		log.Warn("using insecure secret token authorization")
		auth := secretTokenAuthorization{
			log:         log,
			secretToken: config.Gitserver.SecretToken,
		}
		authCallback = auth.authorize
	} else {
		keyBytes, err := base64.StdEncoding.DecodeString(config.Gitserver.PublicKeyBase64)
		if err != nil {
			log.Error("failed to parse the base64-encoded public key", "err", err)
			os.Exit(1)
		}

		auth := bearerAuthorization{
			log:       log,
			publicKey: ed25519.PublicKey(keyBytes),
		}
		authCallback = auth.authorize
	}

	protocol := gitserver.NewGitProtocol(
		authCallback,
		referenceDiscovery,
		config.Gitserver.AllowDirectPushToMaster,
		gitserver.OverallWallTimeHardLimit,
		&gitserver.LibinteractiveCompiler{
			LibinteractiveJarPath: config.Gitserver.LibinteractivePath,
			Log:                   log,
		},
		log,
	)

	var servers []*http.Server
	var wg sync.WaitGroup
	gitServer := &http.Server{
		Addr:    fmt.Sprintf(":%d", config.Gitserver.Port),
		Handler: muxHandler(config.Gitserver.RootPath, protocol, log),
	}
	servers = append(servers, gitServer)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := gitServer.ListenAndServe(); err != http.ErrServerClosed {
			log.Error("gitServer ListenAndServe", "err", err)
		}
	}()
	log.Info(
		"omegaUp gitserver ready",
		"version", ProgramVersion,
		"address", gitServer.Addr,
	)

	if config.Gitserver.PprofPort > 0 {
		pprofServeMux := http.NewServeMux()
		pprofServeMux.HandleFunc("/debug/pprof/", pprof.Index)
		pprofServeMux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		pprofServeMux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		pprofServeMux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		pprofServeMux.HandleFunc("/debug/pprof/trace", pprof.Trace)
		pprofServer := &http.Server{
			Addr:    fmt.Sprintf("localhost:%d", config.Gitserver.PprofPort),
			Handler: pprofServeMux,
		}
		servers = append(servers, pprofServer)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := pprofServer.ListenAndServe(); err != http.ErrServerClosed {
				log.Error("pprof ListenAndServe", "err", err)
			}
		}()
		log.Info(
			"pprof server ready",
			"address", pprofServer.Addr,
		)
	}
	daemon.SdNotify(false, "READY=1")

	<-stopChan

	daemon.SdNotify(false, "STOPPING=1")
	log.Info("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	for _, server := range servers {
		server.Shutdown(ctx)
	}

	cancel()
	wg.Wait()

	log.Info("Server gracefully stopped.")
}
