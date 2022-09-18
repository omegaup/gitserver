package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/omegaup/githttp/v2"
	"github.com/omegaup/gitserver"
	"github.com/omegaup/gitserver/request"
	"github.com/omegaup/go-base/logging/log15/v3"
	nrtracing "github.com/omegaup/go-base/tracing/newrelic/v3"
	"github.com/omegaup/go-base/v3/logging"
	"github.com/omegaup/go-base/v3/tracing"

	"github.com/coreos/go-systemd/v22/daemon"
	git "github.com/libgit2/git2go/v33"
	newrelic "github.com/newrelic/go-agent/v3/newrelic"
)

var (
	configPath = flag.String(
		"config",
		"/etc/omegaup/gitserver/config.json",
		"gitserver configuration file",
	)
	insecureSkipAuthorization = flag.Bool(
		"insecure-skip-authorization",
		false,
		"grant all privileges to all users",
	)
	version = flag.Bool("version", false, "Print the version and exit")

	// ProgramVersion is the version of the code from which the binary was built from.
	ProgramVersion string
)

func referenceDiscovery(
	ctx context.Context,
	repository *git.Repository,
	referenceName string,
) bool {
	requestContext := request.FromContext(ctx)
	if requestContext.Request.CanViewAllRefs {
		return true
	}
	if requestContext.Request.HasSolved {
		// Solvers can also view the protected branch
		if referenceName == "refs/heads/protected" {
			return true
		}
	}

	if requestContext.Request.CanView {
		// Public problems can be viewed by anyone.
		if referenceName == "refs/heads/public" {
			return true
		}
	}
	return false
}

type muxGitHandler struct {
	log            logging.Logger
	gitHandler     http.Handler
	zipHandler     http.Handler
	metricsHandler http.Handler
	healthHandler  http.Handler
}

func muxHandler(
	app *newrelic.Application,
	port uint16,
	rootPath string,
	protocol *githttp.GitProtocol,
	log logging.Logger,
) http.Handler {
	metrics, metricsHandler := gitserver.SetupMetrics(ProgramVersion)
	tracing := nrtracing.New(app)
	_, wrappedGitHandler := tracing.WrapHandle("/", gitserver.NewGitHandler(gitserver.GitHandlerOpts{
		RootPath: rootPath,
		Protocol: protocol,
		Metrics:  metrics,
		Log:      log,
		Tracing:  tracing,
	}))
	_, wrappedZipHandler := tracing.WrapHandle("/", gitserver.NewZipHandler(gitserver.ZipHandlerOpts{
		RootPath: rootPath,
		Protocol: protocol,
		Metrics:  metrics,
		Log:      log,
		Tracing:  tracing,
	}))
	_, wrappedHealthHandler := tracing.WrapHandle("/health", gitserver.HealthHandler(
		rootPath,
		port,
	))
	_, wrappedMetricsHandler := tracing.WrapHandle("/metrics", metricsHandler)
	return &muxGitHandler{
		log:            log,
		gitHandler:     wrappedGitHandler,
		zipHandler:     wrappedZipHandler,
		metricsHandler: wrappedMetricsHandler,
		healthHandler:  wrappedHealthHandler,
	}
}

func (h *muxGitHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	splitPath := strings.Split(r.URL.Path[1:], "/")
	if len(splitPath) == 2 && splitPath[0] == "health" {
		h.healthHandler.ServeHTTP(w, r)
	} else if len(splitPath) >= 1 && splitPath[0] == "metrics" {
		h.metricsHandler.ServeHTTP(w, r)
	} else if len(splitPath) == 2 && splitPath[1] == "git-upload-zip" ||
		len(splitPath) == 3 && splitPath[1] == "rename-repository" {
		txn := tracing.FromContext(r.Context())
		txn.SetName(r.Method + " /:repo/" + splitPath[1])
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

	log, err := log15.New(config.Logging.Level, config.Logging.JSON)
	if err != nil {
		panic(err)
	}

	var app *newrelic.Application
	if config.NewRelic.License != "" {
		app, err = newrelic.NewApplication(
			newrelic.ConfigAppName(config.NewRelic.AppName),
			newrelic.ConfigLicense(config.NewRelic.License),
			newrelic.ConfigLogger(log),
			newrelic.ConfigDistributedTracerEnabled(true),
		)
		if err != nil {
			panic(err)
		}
	}

	if config.Gitserver.RootPath == "" {
		log.Error("root path cannot be empty. Please specify one with -root", nil)
		os.Exit(1)
	}

	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, syscall.SIGINT, syscall.SIGTERM)

	authCallback, err := createAuthorizationCallback(config, log)
	if err != nil {
		log.Error(
			"failed to create the authorization callback",
			map[string]any{
				"err": err,
			},
		)
		os.Exit(1)
	}

	protocol := gitserver.NewGitProtocol(gitserver.GitProtocolOpts{
		GitProtocolOpts: githttp.GitProtocolOpts{
			AuthCallback:               authCallback,
			ReferenceDiscoveryCallback: referenceDiscovery,
			Log:                        log,
		},
		AllowDirectPushToMaster:  config.Gitserver.AllowDirectPushToMaster,
		HardOverallWallTimeLimit: gitserver.OverallWallTimeHardLimit,
		InteractiveSettingsCompiler: &gitserver.LibinteractiveCompiler{
			LibinteractiveJarPath: config.Gitserver.LibinteractivePath,
			Log:                   log,
		},
	})

	var servers []*http.Server
	var wg sync.WaitGroup
	writeTimeout := 2 * time.Minute // Frontend has a 120s second timeout.
	gitServer := &http.Server{
		Addr: fmt.Sprintf(":%d", config.Gitserver.Port),
		Handler: http.TimeoutHandler(
			muxHandler(
				app,
				config.Gitserver.Port,
				config.Gitserver.RootPath,
				protocol,
				log,
			),
			writeTimeout,
			"Timeout",
		),
		WriteTimeout: writeTimeout,
	}
	servers = append(servers, gitServer)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := gitServer.ListenAndServe(); err != http.ErrServerClosed {
			log.Error(
				"gitServer ListenAndServe",
				map[string]any{
					"err": err,
				},
			)
		}
	}()
	log.Info(
		"omegaUp gitserver ready",
		map[string]any{
			"version": ProgramVersion,
			"address": gitServer.Addr,
		},
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
				log.Error(
					"pprof ListenAndServe",
					map[string]any{
						"err": err,
					},
				)
			}
		}()
		log.Info(
			"pprof server ready",
			map[string]any{
				"address": pprofServer.Addr,
			},
		)
	}
	daemon.SdNotify(false, "READY=1")

	<-stopChan

	daemon.SdNotify(false, "STOPPING=1")
	log.Info("Shutting down server...", nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	for _, server := range servers {
		server.Shutdown(ctx)
	}

	cancel()
	wg.Wait()

	log.Info("Server gracefully stopped.", nil)
}
