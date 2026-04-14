package main

import (
	"log/slog"
	"net/http"

	"github.com/evalops/service-runtime/httpkit"
	"github.com/evalops/service-runtime/observability"
)

func newObservedHandler(logger *slog.Logger, metrics *observability.Metrics, next http.Handler) http.Handler {
	observed := httpkit.WithRequestID(observability.RequestLoggingMiddleware(logger, metrics)(next))
	if metrics == nil {
		return observed
	}

	metricsHandler := metrics.Handler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/metrics" {
			metricsHandler.ServeHTTP(w, r)
			return
		}
		observed.ServeHTTP(w, r)
	})
}
