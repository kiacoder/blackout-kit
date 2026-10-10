package hyperpulse

import (
	"math"
	"time"
)

// AdaptivePolicy chooses a parity count from a bounded history of observed
// RTT and packet-drop samples. A zero WindowSize selects a default window of 16.
const maxPolicyWindow = 1024

type AdaptivePolicy struct {
	MinParity  int
	MaxParity  int
	WindowSize int

	samples []policySample
	next    int
	count   int
}

type policySample struct {
	rtt  time.Duration
	drop uint64
	sent uint64
}

// Observe records one measurement and returns a parity count constrained by
// MinParity and MaxParity. A negative RTT or drops greater than sent are
// sanitized to zero and sent respectively.
func (p *AdaptivePolicy) Observe(rtt time.Duration, dropped, sent uint64) int {
	minParity, maxParity := p.MinParity, p.MaxParity
	if minParity < 0 {
		minParity = 0
	}
	if maxParity < minParity {
		maxParity = minParity
	}
	if rtt < 0 {
		rtt = 0
	}
	if dropped > sent {
		dropped = sent
	}

	windowSize := p.WindowSize
	if windowSize <= 0 {
		windowSize = 16
	} else if windowSize > maxPolicyWindow {
		windowSize = maxPolicyWindow
	}
	if cap(p.samples) != windowSize {
		p.samples = make([]policySample, windowSize)
		p.next, p.count = 0, 0
	}
	p.samples[p.next] = policySample{rtt: rtt, drop: dropped, sent: sent}
	p.next = (p.next + 1) % windowSize
	if p.count < windowSize {
		p.count++
	}

	var droppedTotal, sentTotal float64
	var rttSum, rttSquares float64
	for i := 0; i < p.count; i++ {
		sample := p.samples[i]
		droppedTotal += float64(sample.drop)
		sentTotal += float64(sample.sent)
		ms := float64(sample.rtt) / float64(time.Millisecond)
		rttSum += ms
		rttSquares += ms * ms
	}

	dropRate := 0.0
	if sentTotal > 0 {
		dropRate = droppedTotal / sentTotal
	}
	meanRTT := rttSum / float64(p.count)
	variance := rttSquares/float64(p.count) - meanRTT*meanRTT
	if variance < 0 {
		variance = 0
	}
	rttVariation := math.Sqrt(variance)

	span := float64(maxParity - minParity)
	increase := 0.0
	if sentTotal > 0 {
		increase += math.Ceil(dropRate * span)
	}
	if rttVariation >= 25 {
		increase += math.Ceil(span / 2)
	}
	if increase >= span {
		return maxParity
	}
	return minParity + int(increase)
}
