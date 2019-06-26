package gitserver

import (
	base "github.com/omegaup/go-base"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"
)

var (
	gauges = map[string]prometheus.Gauge{}

	counters = map[string]prometheus.Counter{}

	summaries = map[string]prometheus.Summary{}
)

type prometheusMetrics struct {
}

func (p *prometheusMetrics) GaugeAdd(name string, value float64) {
	if gauge, ok := gauges[name]; ok {
		gauge.Add(value)
	}
}

func (p *prometheusMetrics) CounterAdd(name string, value float64) {
	if counter, ok := counters[name]; ok {
		counter.Add(value)
	}
}

func (p *prometheusMetrics) SummaryObserve(name string, value float64) {
	if summary, ok := summaries[name]; ok {
		summary.Observe(value)
	}
}

// SetupMetrics sets up the metrics for the gitserver.
func SetupMetrics() (base.Metrics, http.Handler) {
	for _, gauge := range gauges {
		prometheus.MustRegister(gauge)
	}
	for _, counter := range counters {
		prometheus.MustRegister(counter)
	}
	for _, summary := range summaries {
		prometheus.MustRegister(summary)
	}

	return &prometheusMetrics{}, promhttp.Handler()
}
