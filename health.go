package gitserver

import (
	"bytes"
	"context"
	_ "embed" // Required by the `go:embed` comment below.
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"time"
)

//go:embed testproblem.zip
var testproblemZip []byte

// HealthHandler is an implementation of k8s readiness and liveness checks. The
// liveness check just returns HTTP 200 (because the server is reachable), but
// the readiness check tries to interact with the service by requesting the
// settings.json file of the sumas problem. Getting a 404 is fine.
func HealthHandler(rootPath string, port uint16) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health/live", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/health/ready", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		if _, err := os.Stat(path.Join(rootPath, ":testproblem")); os.IsNotExist(err) {
			// Creating problem!
			req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("http://localhost:%d/:testproblem/git-upload-zip?create=true&message=Test&acceptsSubmissions=true&updatePublished=true&mergeStrategy=theirs", port), nil)
			if err != nil {
				w.WriteHeader(http.StatusServiceUnavailable)
				w.Write([]byte(fmt.Sprintf("git-upload-zip request: %v", err)))
				return
			}

			req.Header.Add("Authorization", "omegaup:health")
			req.Header.Add("Content-Type", "application/zip")
			req.Body = io.NopCloser(bytes.NewReader(testproblemZip))
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				w.WriteHeader(http.StatusServiceUnavailable)
				w.Write([]byte(fmt.Sprintf("git-upload-zip request: %v", err)))
				return
			}
			contents, readErr := io.ReadAll(res.Body)
			if readErr != nil {
				contents = append(contents, []byte(fmt.Sprintf(", error=%v", readErr))...)
			}
			res.Body.Close()

			if res.StatusCode != 200 {
				w.WriteHeader(http.StatusServiceUnavailable)
				w.Write([]byte(fmt.Sprintf("git-upload-zip HTTP/%d. headers: %v, body: %v", res.StatusCode, res.Header, string(contents))))
				return
			}
		}

		req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("http://localhost:%d/:testproblem/+/private/settings.json", port), nil)
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(fmt.Sprintf("request: %v", err)))
			return
		}

		req.Header.Add("Authorization", "omegaup:health")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(fmt.Sprintf("request: %v", err)))
			return
		}
		res.Body.Close()

		if res.StatusCode != 200 {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(fmt.Sprintf("HTTP/%d", res.StatusCode)))
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	return mux
}
