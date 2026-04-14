package promutil

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/prometheus/client_golang/prometheus"
)

// MetricPrefix normalizes a service name into a Prometheus metric prefix.
func MetricPrefix(serviceName string) string {
	serviceName = strings.TrimSpace(serviceName)
	if serviceName == "" {
		return "service"
	}

	var builder strings.Builder
	for index, runeValue := range serviceName {
		switch {
		case unicode.IsLetter(runeValue), unicode.IsDigit(runeValue):
			builder.WriteRune(unicode.ToLower(runeValue))
		default:
			builder.WriteByte('_')
		}
		if index == 0 && unicode.IsDigit(runeValue) {
			builder.WriteByte('_')
		}
	}

	prefix := strings.Trim(builder.String(), "_")
	if prefix == "" {
		return "service"
	}
	if prefix[0] >= '0' && prefix[0] <= '9' {
		return "service_" + prefix
	}
	return prefix
}

// RegisterGaugeVec registers collector and returns an existing compatible collector when present.
func RegisterGaugeVec(registerer prometheus.Registerer, collector *prometheus.GaugeVec) (*prometheus.GaugeVec, error) {
	if err := registerer.Register(collector); err != nil {
		alreadyRegistered, ok := err.(prometheus.AlreadyRegisteredError)
		if !ok {
			return nil, err
		}
		existing, ok := alreadyRegistered.ExistingCollector.(*prometheus.GaugeVec)
		if !ok {
			return nil, err
		}
		return existing, nil
	}
	return collector, nil
}

// RegisterCounterVec registers collector and returns an existing compatible collector when present.
func RegisterCounterVec(registerer prometheus.Registerer, collector *prometheus.CounterVec) (*prometheus.CounterVec, error) {
	if err := registerer.Register(collector); err != nil {
		alreadyRegistered, ok := err.(prometheus.AlreadyRegisteredError)
		if !ok {
			return nil, err
		}
		existing, ok := alreadyRegistered.ExistingCollector.(*prometheus.CounterVec)
		if !ok {
			return nil, err
		}
		return existing, nil
	}
	return collector, nil
}

// RegisterHistogram registers collector and returns an existing compatible collector when present.
func RegisterHistogram(registerer prometheus.Registerer, collector prometheus.Histogram) (prometheus.Histogram, error) {
	if err := registerer.Register(collector); err != nil {
		alreadyRegistered, ok := err.(prometheus.AlreadyRegisteredError)
		if !ok {
			return nil, err
		}
		existing, ok := alreadyRegistered.ExistingCollector.(prometheus.Histogram)
		if !ok {
			return nil, fmt.Errorf("register histogram: existing collector has unexpected type %T", alreadyRegistered.ExistingCollector)
		}
		return existing, nil
	}
	return collector, nil
}

// RegisterHistogramVec registers collector and returns an existing compatible collector when present.
func RegisterHistogramVec(registerer prometheus.Registerer, collector *prometheus.HistogramVec) (*prometheus.HistogramVec, error) {
	if err := registerer.Register(collector); err != nil {
		alreadyRegistered, ok := err.(prometheus.AlreadyRegisteredError)
		if !ok {
			return nil, err
		}
		existing, ok := alreadyRegistered.ExistingCollector.(*prometheus.HistogramVec)
		if !ok {
			return nil, err
		}
		return existing, nil
	}
	return collector, nil
}
