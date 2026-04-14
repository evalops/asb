package main

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/evalops/service-runtime/observability"
	"github.com/prometheus/client_golang/prometheus"
)

func TestNewObservedHandlerServesMetrics(t *testing.T) {
	t.Parallel()

	registry := prometheus.NewRegistry()
	metrics, err := observability.NewMetrics("asb", observability.MetricsOptions{
		Registerer: registry,
		Gatherer:   registry,
	})
	if err != nil {
		t.Fatalf("NewMetrics() error = %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/test", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	handler := newObservedHandler(discardLogger(), metrics, mux)
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/test", nil))

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if got := recorder.Header().Get("Content-Type"); !strings.Contains(got, "text/plain") {
		t.Fatalf("content-type = %q, want Prometheus text output", got)
	}
	if body := recorder.Body.String(); !strings.Contains(body, "asb_http_requests_total") {
		t.Fatalf("body = %q, want metrics payload", body)
	}
}

func TestNewObservedHandlerRecordsRequestMetrics(t *testing.T) {
	t.Parallel()

	registry := prometheus.NewRegistry()
	metrics, err := observability.NewMetrics("asb", observability.MetricsOptions{
		Registerer: registry,
		Gatherer:   registry,
	})
	if err != nil {
		t.Fatalf("NewMetrics() error = %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/test", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	handler := newObservedHandler(discardLogger(), metrics, mux)
	req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusCreated)
	}
	if got := recorder.Header().Get("X-Request-Id"); got == "" {
		t.Fatal("expected X-Request-Id response header")
	}

	metricsRecorder := httptest.NewRecorder()
	handler.ServeHTTP(metricsRecorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	metricsBody := metricsRecorder.Body.String()
	if !strings.Contains(metricsBody, `asb_http_requests_total{method="GET",route="/v1/test",status="201"} 1`) {
		t.Fatalf("metrics body = %q, want request counter sample", metricsBody)
	}
	if !strings.Contains(metricsBody, `asb_http_request_duration_seconds_count{method="GET",route="/v1/test",status="201"} 1`) {
		t.Fatalf("metrics body = %q, want request duration sample", metricsBody)
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
