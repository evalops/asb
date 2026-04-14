package worker

import (
	"time"

	"github.com/evalops/asb/internal/app"
	"github.com/evalops/asb/internal/promutil"
	"github.com/prometheus/client_golang/prometheus"
)

type MetricsOptions struct {
	Registerer      prometheus.Registerer
	DurationBuckets []float64
}

type Metrics struct {
	processed *prometheus.CounterVec
	duration  prometheus.Histogram
}

func NewMetrics(serviceName string, opts MetricsOptions) (*Metrics, error) {
	if opts.Registerer == nil {
		opts.Registerer = prometheus.DefaultRegisterer
	}
	if len(opts.DurationBuckets) == 0 {
		opts.DurationBuckets = prometheus.DefBuckets
	}

	prefix := promutil.MetricPrefix(serviceName)
	processed, err := promutil.RegisterCounterVec(
		opts.Registerer,
		prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: prefix + "_cleanup_processed_total",
				Help: "Count of ASB cleanup items processed by type.",
			},
			[]string{"item_type"},
		),
	)
	if err != nil {
		return nil, err
	}

	duration, err := promutil.RegisterHistogram(
		opts.Registerer,
		prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    prefix + "_cleanup_pass_seconds",
				Help:    "Duration of ASB cleanup passes in seconds.",
				Buckets: opts.DurationBuckets,
			},
		),
	)
	if err != nil {
		return nil, err
	}

	return &Metrics{
		processed: processed,
		duration:  duration,
	}, nil
}

func (m *Metrics) recordCleanupPass(stats *app.CleanupStats, duration time.Duration) {
	if m == nil {
		return
	}
	m.duration.Observe(duration.Seconds())
	if stats == nil {
		return
	}
	m.processed.WithLabelValues("approvals").Add(float64(stats.ApprovalsExpired))
	m.processed.WithLabelValues("sessions").Add(float64(stats.SessionsExpired))
	m.processed.WithLabelValues("grants").Add(float64(stats.GrantsExpired))
	m.processed.WithLabelValues("artifacts").Add(float64(stats.ArtifactsExpired))
}
