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

	git "github.com/libgit2/git2go/v32"
	"github.com/omegaup/githttp"
	"github.com/omegaup/gitserver"
	"github.com/omegaup/gitserver/request"
	base "github.com/omegaup/go-base/v2"

	"github.com/coreos/go-systemd/v22/daemon"
	"github.com/inconshreveable/log15"
	"github.com/newrelic/go-agent/v3/newrelic"
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
	log     log15.Logger

	// ProgramVersion is the version of the code from which the binary was built from.
	ProgramVersion string
)

func referenceDiscovery(
	ctx context.Context,
	repository *git.Repository,
	referenceName string,
) bool {
	requestContext := request.FromContext(ctx)
	if requestContext.Request.CanEdit {
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
	log            log15.Logger
	gitHandler     http.Handler
	zipHandler     http.Handler
	metricsHandler http.Handler
}

func muxHandler(
	app *newrelic.Application,
	rootPath string,
	protocol *githttp.GitProtocol,
	log log15.Logger,
) http.Handler {
	metrics, metricsHandler := gitserver.SetupMetrics(ProgramVersion)
	_, wrappedGitHandler := newrelic.WrapHandle(app, "/", gitserver.GitHandler(rootPath, protocol, metrics, log))
	_, wrappedZipHandler := newrelic.WrapHandle(app, "/", gitserver.ZipHandler(rootPath, protocol, metrics, log))
	return &muxGitHandler{
		log:            log,
		gitHandler:     wrappedGitHandler,
		zipHandler:     wrappedZipHandler,
		metricsHandler: metricsHandler,
	}
}

func (h *muxGitHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	splitPath := strings.Split(r.URL.Path[1:], "/")
	if len(splitPath) >= 1 && splitPath[0] == "metrics" {
		h.metricsHandler.ServeHTTP(w, r)
	} else if len(splitPath) == 2 && splitPath[1] == "git-upload-zip" ||
		len(splitPath) == 3 && splitPath[1] == "rename-repository" {
		txn := newrelic.FromContext(r.Context())
		txn.SetName(r.Method + " " + splitPath[1])
		h.zipHandler.ServeHTTP(w, r)
	} else {
		h.gitHandler.ServeHTTP(w, r)
	}
}

type log15Logger struct {
	log log15.Logger
}

func (l *log15Logger) Error(msg string, context map[string]interface{}) {
	l.log.Error(msg, log15.Ctx(context))
}

func (l *log15Logger) Warn(msg string, context map[string]interface{}) {
	l.log.Warn(msg, log15.Ctx(context))
}

func (l *log15Logger) Info(msg string, context map[string]interface{}) {
	l.log.Info(msg, log15.Ctx(context))
}

func (l *log15Logger) Debug(msg string, context map[string]interface{}) {
	l.log.Debug(msg, log15.Ctx(context))
}

func (l *log15Logger) DebugEnabled() bool {
	return true
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
		log, err = base.RotatingLog(
			config.Logging.File,
			config.Logging.Level,
			config.Logging.JSON,
		)
		if err != nil {
			panic(err)
		}
	} else if config.Logging.Level == "debug" {
		log = base.StderrLog(config.Logging.JSON)
	} else {
		log = log15.New()
		log.SetHandler(base.ErrorCallerStackHandler(
			log15.LvlInfo,
			base.StderrHandler(config.Logging.JSON),
		))
	}

	var app *newrelic.Application
	if config.NewRelic.License != "" {
		app, err = newrelic.NewApplication(
			newrelic.ConfigAppName(config.NewRelic.AppName),
			newrelic.ConfigLicense(config.NewRelic.License),
			newrelic.ConfigLogger(&log15Logger{log: log}),
			newrelic.ConfigDistributedTracerEnabled(true),
		)
		if err != nil {
			panic(err)
		}
	}

	if config.Gitserver.RootPath == "" {
		log.Error("root path cannot be empty. Please specify one with -root")
		os.Exit(1)
	}

	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, syscall.SIGINT, syscall.SIGTERM)

	authCallback, err := createAuthorizationCallback(config, log)
	if err != nil {
		log.Error("failed to create the authorization callback", "err", err)
		os.Exit(1)
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
		Handler: muxHandler(app, config.Gitserver.RootPath, protocol, log),
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
