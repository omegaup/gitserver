package main

import (
	"context"
	"errors"
	"io"
	"io/ioutil"
	"net"
	"net/http/httptest"
	"os"
	"path"
	"strconv"
	"testing"

	"github.com/omegaup/githttp/v2"
	"github.com/omegaup/gitserver"
	"github.com/omegaup/go-base/logging/log15"
)

var (
	fakeInteractiveSettingsCompiler = &gitserver.FakeInteractiveSettingsCompiler{
		Settings: nil,
		Err:      errors.New("unsupported"),
	}
)

func TestHealth(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", t.Name())
	if err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}
	if os.Getenv("PRESERVE") == "" {
		defer os.RemoveAll(tmpDir)
	}

	ctx := context.Background()

	log, err := log15.New("info", false)
	if err != nil {
		t.Fatalf("Failed to create log: %v", err)
	}
	ts := httptest.NewUnstartedServer(nil)
	_, portString, err := net.SplitHostPort(ts.Listener.Addr().String())
	if err != nil {
		t.Fatalf("port: %v", err)
	}
	port, err := strconv.ParseInt(portString, 10, 32)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	config := DefaultConfig()
	config.Gitserver.Port = uint16(port)
	authorize, err := createAuthorizationCallback(&config, log)
	if err != nil {
		t.Fatalf("authorization callback: %v", err)
	}

	ts.Config.Handler = muxHandler(
		nil,
		config.Gitserver.Port,
		tmpDir,
		gitserver.NewGitProtocol(gitserver.GitProtocolOpts{
			GitProtocolOpts: githttp.GitProtocolOpts{
				AuthCallback: authorize,
				Log:          log,
			},
			HardOverallWallTimeLimit:    gitserver.OverallWallTimeHardLimit,
			InteractiveSettingsCompiler: fakeInteractiveSettingsCompiler,
		}),
		log,
	)
	ts.Start()
	defer ts.Close()

	problemAlias := "sumas"

	repo, err := gitserver.InitRepository(ctx, path.Join(tmpDir, problemAlias))
	if err != nil {
		t.Fatalf("Failed to initialize git repository: %v", err)
	}
	defer repo.Free()

	for _, path := range []string{"/health/live", "/health/ready"} {
		path := path
		t.Run(path, func(t *testing.T) {
			res, err := ts.Client().Get(ts.URL + path)
			if err != nil {
				t.Fatalf("get: %v", err)
			}
			defer res.Body.Close()

			if res.StatusCode != 200 {
				body, _ := io.ReadAll(res.Body)
				t.Fatalf("health check failure: HTTP %d: %v", res.StatusCode, string(body))
			}
		})
	}
}
