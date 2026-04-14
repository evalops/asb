package bootstrap

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	miniredis "github.com/alicebob/miniredis/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	goredis "github.com/redis/go-redis/v9"
)

func TestInstrumentRedisClientRecordsCommandMetrics(t *testing.T) {
	t.Parallel()

	server, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run() error = %v", err)
	}
	defer server.Close()

	registry := prometheus.NewRegistry()
	client := goredis.NewClient(&goredis.Options{Addr: server.Addr()})
	defer func() { _ = client.Close() }()

	if err := instrumentRedisClient(client, registry); err != nil {
		t.Fatalf("instrumentRedisClient() error = %v", err)
	}
	if err := client.Set(context.Background(), "relay:test", "ok", 0).Err(); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	if err := client.Get(context.Background(), "relay:test").Err(); err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	recorder := httptest.NewRecorder()
	promhttp.HandlerFor(registry, promhttp.HandlerOpts{}).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	body := recorder.Body.String()
	if !strings.Contains(body, `asb_redis_commands_total{command="set",status="ok"} 1`) {
		t.Fatalf("metrics body = %q, want Redis set counter", body)
	}
	if !strings.Contains(body, `asb_redis_commands_total{command="get",status="ok"} 1`) {
		t.Fatalf("metrics body = %q, want Redis get counter", body)
	}
	if !strings.Contains(body, `asb_redis_command_duration_seconds_count{command="set",status="ok"} 1`) {
		t.Fatalf("metrics body = %q, want Redis set duration histogram", body)
	}
}
