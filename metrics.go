package gitserver

import (
	base "github.com/omegaup/go-base"
	"github.com/prometheus/client_golang/prometheus"
	"net/http"
)

var (
	gauges = map[string]prometheus.Gauge{}

	counters = map[string]prometheus.Counter{}

	summaries = map[string]prometheus.Summary{
		"grader_queue_delay_seconds": prometheus.NewSummary(prometheus.SummaryOpts{
			Namespace:  "quark",
			Subsystem:  "grader",
			Help:       "The duration of a run in any queue",
			Name:       "queue_delay_seconds",
			Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
		}),
	}
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

	return &prometheusMetrics{}, prometheus.Handler()
}
