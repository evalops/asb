package worker_test

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/evalops/asb/internal/app"
	"github.com/evalops/asb/internal/worker"
)

func TestRunner_RunOnce(t *testing.T) {
	t.Parallel()

	service := &fakeCleanupService{
		stats: &app.CleanupStats{
			ApprovalsExpired: 1,
			SessionsExpired:  2,
			GrantsExpired:    3,
			ArtifactsExpired: 4,
		},
	}
	runner := worker.NewRunner(worker.Config{
		Service: service,
		Limit:   50,
		Logger:  slog.New(slog.NewTextHandler(testWriter{t}, nil)),
	})

	stats, err := runner.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if service.calls != 1 {
		t.Fatalf("service calls = %d, want 1", service.calls)
	}
	if stats.GrantsExpired != 3 {
		t.Fatalf("stats = %#v, want grants expired = 3", stats)
	}
}

func TestRunner_RunPropagatesErrors(t *testing.T) {
	t.Parallel()

	service := &fakeCleanupService{err: errors.New("boom")}
	runner := worker.NewRunner(worker.Config{
		Service:  service,
		Limit:    50,
		Interval: 5 * time.Millisecond,
		Logger:   slog.New(slog.NewTextHandler(testWriter{t}, nil)),
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := runner.Run(ctx); err == nil {
		t.Fatal("Run() error = nil, want non-nil")
	}
}

func TestRunner_RunDrainsCurrentPassBeforeExit(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})
	release := make(chan struct{})
	service := &fakeCleanupService{
		stats: &app.CleanupStats{},
		runCleanupOnce: func(ctx context.Context, limit int) (*app.CleanupStats, error) {
			close(started)
			<-release
			return &app.CleanupStats{}, nil
		},
	}
	runner := worker.NewRunner(worker.Config{
		Service:  service,
		Limit:    50,
		Interval: 5 * time.Millisecond,
		Logger:   slog.New(slog.NewTextHandler(testWriter{t}, nil)),
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runner.Run(ctx)
	}()

	<-started
	cancel()
	close(release)

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run() did not exit after draining current pass")
	}

	service.mu.Lock()
	calls := service.calls
	service.mu.Unlock()
	if calls != 1 {
		t.Fatalf("service calls = %d, want 1", calls)
	}
}

type fakeCleanupService struct {
	stats          *app.CleanupStats
	err            error
	runCleanupOnce func(context.Context, int) (*app.CleanupStats, error)
	calls          int
	mu             sync.Mutex
}

func (f *fakeCleanupService) RunCleanupOnce(ctx context.Context, limit int) (*app.CleanupStats, error) {
	f.mu.Lock()
	f.calls++
	runCleanupOnce := f.runCleanupOnce
	stats := f.stats
	err := f.err
	f.mu.Unlock()

	if runCleanupOnce != nil {
		return runCleanupOnce(ctx, limit)
	}
	if err != nil {
		return nil, err
	}
	return stats, nil
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(string(p))
	return len(p), nil
}
