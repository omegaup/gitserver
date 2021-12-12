package main

import (
	"errors"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
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

	log, err := log15.New("info", false)
	if err != nil {
		t.Fatalf("Failed to create log: %v", err)
	}
	config := &Config{
		Gitserver: GitserverConfig{
			AllowDirectPushToMaster: true,
		},
	}
	authCallback := omegaupAuthorization{
		log:    log,
		config: config,
	}
	ts := httptest.NewUnstartedServer(nil)
	ts.Config.Handler = muxHandler(
		nil,
		uint16(ts.Listener.Addr().(*net.TCPAddr).Port),
		tmpDir,
		gitserver.NewGitProtocol(gitserver.GitProtocolOpts{
			GitProtocolOpts: githttp.GitProtocolOpts{
				AuthCallback: authCallback.authorize,
				Log:          log,
			},
			AllowDirectPushToMaster:     config.Gitserver.AllowDirectPushToMaster,
			HardOverallWallTimeLimit:    gitserver.OverallWallTimeHardLimit,
			InteractiveSettingsCompiler: fakeInteractiveSettingsCompiler,
		}),
		log,
	)
	ts.Start()
	defer ts.Close()

	res, err := ts.Client().Get(ts.URL + "/health/live")
	if err != nil {
		t.Fatalf("Failed to create pre-pull request: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("/health/live failed. status: %v, headers: %v", res.StatusCode, res.Header)
	}

	// Run this twice because the first attempt will create the problem.
	for i := 0; i < 2; i++ {
		res, err = ts.Client().Get(ts.URL + "/health/ready")
		if err != nil {
			t.Fatalf("Failed to create pre-pull request: %v", err)
		}
		contents, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatalf("Failed to read response: %v", err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("/health/ready failed. status: %v, headers: %v, body: %v", res.StatusCode, res.Header, string(contents))
		}
	}
}
