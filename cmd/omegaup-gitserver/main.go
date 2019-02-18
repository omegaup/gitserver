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
	"syscall"
	"time"
)

var (
	rootPath                = flag.String("root", "", "Root path of all repositories")
	publicKeyBase64         = flag.String("public-key", "gKEg5JlIOA1BsIxETZYhjd+ZGchY/rZeQM0GheAWvXw=", "Public key of the omegaUp frontend")
	secretToken             = flag.String("secret-token", "", "A secret token to use instead of resorting to PKI for speeding up tests")
	port                    = flag.Int("port", 33861, "Port in which the server will listen")
	pprofPort               = flag.Int("pprof-port", 33862, "Port in which the pprof server will listen")
	libinteractivePath      = flag.String("libinteractive-path", "/usr/share/java/libinteractive.jar", "Path of libinteractive.jar")
	allowDirectPushToMaster = flag.Bool("allow-direct-push-to-master", false, "Allow direct push to master")
	logFile                 = flag.String("log-file", "", "Redirect logs to file")
	verbose                 = flag.Bool("verbose", false, "Verbose logging")
	version                 = flag.Bool("version", false, "Print the version and exit")
	log                     log15.Logger

	// ProgramVersion is the version of the code from which the binary was built from.
	ProgramVersion string
)

type bearerAuthorization struct {
	log       log15.Logger
	publicKey ed25519.PublicKey
}

func (a *bearerAuthorization) parseBearerAuth(auth string) (username, problem string, ok bool) {
	const prefix = "Bearer "
	// Case insensitive prefix match. See Issue 22736.
	if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return
	}

	var jsonToken paseto.JSONToken
	var footer string
	if err := paseto.NewV2().Verify(auth[len(prefix):], a.publicKey, &jsonToken, &footer); err != nil {
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

func (a *bearerAuthorization) authorize(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	repositoryName string,
	operation githttp.GitOperation,
) (githttp.AuthorizationLevel, string) {
	username, problem, ok := a.parseBearerAuth(r.Header.Get("Authorization"))
	if !ok {
		w.Header().Set("WWW-Authenticate", "Bearer realm=\"omegaUp gitserver\"")
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
	username, ok := a.parseSecretTokenAuth(r.Header.Get("Authorization"))
	if !ok {
		w.Header().Set("WWW-Authenticate", "Bearer realm=\"omegaUp gitserver\"")
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
	log        log15.Logger
	gitHandler http.Handler
	zipHandler http.Handler
}

func muxHandler(
	rootPath string,
	protocol *githttp.GitProtocol,
	log log15.Logger,
) http.Handler {
	return &muxGitHandler{
		log:        log,
		gitHandler: gitserver.GitHandler(rootPath, protocol, log),
		zipHandler: gitserver.ZipHandler(rootPath, protocol, log),
	}
}

func (h *muxGitHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	splitPath := strings.SplitN(r.URL.Path[1:], "/", 2)
	if len(splitPath) == 2 && splitPath[1] == "git-upload-zip" {
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

	if *logFile != "" {
		logLevel := "info"
		if *verbose {
			logLevel = "debug"
		}
		var err error
		if log, err = base.RotatingLog(*logFile, logLevel); err != nil {
			panic(err)
		}
	} else if *verbose {
		log = base.StderrLog()
	} else {
		log = log15.New()
		log.SetHandler(base.ErrorCallerStackHandler(log15.LvlInfo, log15.StderrHandler))
	}

	stopChan := make(chan os.Signal)
	signal.Notify(stopChan, syscall.SIGINT, syscall.SIGTERM)

	var authCallback githttp.AuthorizationCallback
	if *publicKeyBase64 == "" && *secretToken != "" {
		log.Warn("using insecure secret token authorization")
		auth := secretTokenAuthorization{
			log:         log,
			secretToken: *secretToken,
		}
		authCallback = auth.authorize
	} else {
		keyBytes, err := base64.StdEncoding.DecodeString(*publicKeyBase64)
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
		*allowDirectPushToMaster,
		gitserver.OverallWallTimeHardLimit,
		&gitserver.LibinteractiveCompiler{
			LibinteractiveJarPath: *libinteractivePath,
			Log:                   log,
		},
		log,
	)

	if *rootPath == "" {
		log.Error("root path cannot be empty. Please specify one with -root")
		os.Exit(1)
	}

	gitServer := &http.Server{
		Addr:    fmt.Sprintf(":%d", *port),
		Handler: muxHandler(*rootPath, protocol, log),
	}
	go func() {
		if err := gitServer.ListenAndServe(); err != nil {
			log.Error("gitServer ListenAndServe", "err", err)
		}
	}()
	log.Info(fmt.Sprintf("git server ready for connections at http://localhost:%d", *port))

	var pprofServer *http.Server
	if *pprofPort > 0 {
		pprofServeMux := http.NewServeMux()
		pprofServeMux.HandleFunc("/debug/pprof/", pprof.Index)
		pprofServeMux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		pprofServeMux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		pprofServeMux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		pprofServeMux.HandleFunc("/debug/pprof/trace", pprof.Trace)
		pprofServer := &http.Server{
			Addr:    fmt.Sprintf("localhost:%d", *pprofPort),
			Handler: pprofServeMux,
		}
		go func() {
			if err := pprofServer.ListenAndServe(); err != nil {
				log.Error("pprof ListenAndServe", "err", err)
			}
		}()
		log.Info(fmt.Sprintf("pprof server ready for connections at http://localhost:%d", *pprofPort))
	}
	daemon.SdNotify(false, "READY=1")

	<-stopChan

	log.Info("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	gitServer.Shutdown(ctx)
	if pprofServer != nil {
		pprofServer.Shutdown(ctx)
	}

	log.Info("Server gracefully stopped.")
}
