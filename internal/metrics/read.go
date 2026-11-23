package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func counterValue(c prometheus.Counter) float64 {
	m := &dto.Metric{}
	if err := c.Write(m); err != nil || m.Counter == nil {
		return 0
	}
	return m.GetCounter().GetValue()
}

func gaugeValue(g prometheus.Gauge) float64 {
	m := &dto.Metric{}
	if err := g.Write(m); err != nil || m.Gauge == nil {
		return 0
	}
	return m.GetGauge().GetValue()
}

// gatherVec sums a counter vector from the private registry. It is only used
// by the low-frequency management API, never on the forwarding hot path.
func (c *Collector) gatherVec(name string, match map[string]string) float64 {
	families, err := c.reg.Gather()
	if err != nil {
		return 0
	}
	var total float64
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.GetMetric() {
			if !matchesLabels(metric.GetLabel(), match) {
				continue
			}
			total += metric.GetCounter().GetValue()
		}
	}
	return total
}

func matchesLabels(labels []*dto.LabelPair, match map[string]string) bool {
	for key, want := range match {
		found := false
		for _, pair := range labels {
			if pair.GetName() == key && pair.GetValue() == want {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
