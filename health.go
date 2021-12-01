package gitserver

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// HealthHandler is an implementation of k8s readiness and liveness checks. The
// liveness check just returns HTTP 200 (because the server is reachable), but
// the readiness check tries to interact with the service by requesting the
// settings.json file of the sumas problem. Getting a 404 is fine.
func HealthHandler(port uint16) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health/live", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/health/ready", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("http://localhost:%d/sumas/+/master/settings.json", port), nil)
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
		defer res.Body.Close()

		if res.StatusCode != 200 && res.StatusCode != 404 {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(fmt.Sprintf("HTTP/%d", res.StatusCode)))
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	return mux
}
