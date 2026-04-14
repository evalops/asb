package main

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/evalops/asb/internal/bootstrap"
)

type readinessReporter interface {
	CheckReadiness(ctx context.Context) bootstrap.ReadinessReport
}

func registerHealthHandlers(mux *http.ServeMux, checker readinessReporter, timeout time.Duration) {
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		report := bootstrap.ReadinessReport{
			Ready:  true,
			Checks: map[string]bootstrap.ReadinessCheck{},
		}
		if checker != nil {
			ctx, cancel := context.WithTimeout(r.Context(), timeout)
			defer cancel()
			report = checker.CheckReadiness(ctx)
		}

		status := http.StatusOK
		if !report.Ready {
			status = http.StatusServiceUnavailable
		}
		writeJSON(w, status, report)
	})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	data, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(append(data, '\n'))
}
