package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/evalops/asb/internal/bootstrap"
)

type fakeReadinessReporter struct {
	report bootstrap.ReadinessReport
}

func (f fakeReadinessReporter) CheckReadiness(context.Context) bootstrap.ReadinessReport {
	return f.report
}

func TestRegisterHealthHandlersLiveness(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	registerHealthHandlers(mux, nil, time.Second)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if recorder.Body.String() != "ok" {
		t.Fatalf("body = %q, want %q", recorder.Body.String(), "ok")
	}
}

func TestRegisterHealthHandlersReadiness(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	registerHealthHandlers(mux, fakeReadinessReporter{
		report: bootstrap.ReadinessReport{
			Ready: true,
			Checks: map[string]bootstrap.ReadinessCheck{
				"postgres":            {Status: "ok"},
				"redis":               {Status: "disabled"},
				"session_signing_key": {Status: "ok"},
			},
		},
	}, time.Second)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}

	var payload bootstrap.ReadinessReport
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if !payload.Ready || payload.Checks["postgres"].Status != "ok" {
		t.Fatalf("payload = %#v, want ready postgres check", payload)
	}
}

func TestRegisterHealthHandlersReadinessFailure(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	registerHealthHandlers(mux, fakeReadinessReporter{
		report: bootstrap.ReadinessReport{
			Ready: false,
			Checks: map[string]bootstrap.ReadinessCheck{
				"postgres":            {Status: "error", Message: "dial tcp 127.0.0.1:5432: connect: refused"},
				"redis":               {Status: "ok"},
				"session_signing_key": {Status: "ok"},
			},
		},
	}, time.Second)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusServiceUnavailable)
	}
	if got := recorder.Body.String(); !containsAll(got, "postgres", "error", "connect: refused") {
		t.Fatalf("body = %q, want postgres failure details", got)
	}
}

func containsAll(s string, parts ...string) bool {
	for _, part := range parts {
		if !strings.Contains(s, part) {
			return false
		}
	}
	return true
}
