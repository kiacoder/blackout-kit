// Bug #11 (v1): engine/gdpi_windows.go hardcoded `gdpiChunkSize = 10` and
// engine/sni.go hardcoded `chunkSize := 10`. Neither was reachable from
// configuration, so the single tuning knob that matters against a real DPI box
// could not be changed without recompiling the core — and Python's
// `fragment_tuner.py` could only probe Xray's fragmentation, never the native
// paths. Here chunk sizing and inter-segment delay are config values.
package dialer

import (
	"errors"
	"fmt"
	"io"
	"math/rand"
	"time"
)

// Config is the packet-shaping policy for one connection.
type Config struct {
	// MinChunk and MaxChunk bound each TCP write, in bytes. A DPI box that
	// reassembles only the first N bytes of a handshake never sees the SNI if
	// the ClientHello arrives split across segments smaller than that window.
	MinChunk int
	MaxChunk int

	// MinDelay and MaxDelay bound the pause between consecutive segments.
	// The delay is what actually defeats reassembly: without it the kernel
	// coalesces the writes back into one segment and the fragmentation is
	// invisible on the wire. 100-500us is the usable range — long enough to
	// force separate segments, short enough not to stall the handshake.
	MinDelay time.Duration
	MaxDelay time.Duration

	// FakeSNI replaces the real server_name in the ClientHello. Empty disables
	// rewriting and forwards the handshake untouched.
	FakeSNI string

	// Fragments toggles segmentation. Off means one write per buffer, which is
	// the control case for measurement and for networks where splitting hurts.
	Fragments bool
}

// DefaultConfig returns values in the range the v2 spec calls for.
func DefaultConfig() Config {
	return Config{
		MinChunk:  8,
		MaxChunk:  24,
		MinDelay:  100 * time.Microsecond,
		MaxDelay:  500 * time.Microsecond,
		FakeSNI:   "",
		Fragments: true,
	}
}

// ErrBadChunkRange is returned when bounds are nonsense.
var ErrBadChunkRange = errors.New("dialer: min_chunk must be >= 1 and max_chunk >= min_chunk")

// Validate reports whether the config is usable.
func (c Config) Validate() error {
	if c.MinChunk < 1 {
		return ErrBadChunkRange
	}
	if c.MaxChunk < c.MinChunk {
		return ErrBadChunkRange
	}
	if c.MinDelay < 0 || c.MaxDelay < 0 {
		return errors.New("dialer: delays must not be negative")
	}
	if c.MaxDelay > 0 && c.MinDelay > c.MaxDelay {
		return errors.New("dialer: min_delay must not exceed max_delay")
	}
	if c.FakeSNI != "" {
		return ValidateSNIHost(c.FakeSNI)
	}
	return nil
}

// Normalize returns a usable copy, clamping rather than failing. It is what
// the daemon applies to values arriving over IPC so one bad `tune` call cannot
// take the engine down.
func (c Config) Normalize() Config {
	if c.MinChunk < 1 {
		c.MinChunk = 1
	}
	if c.MaxChunk < c.MinChunk {
		c.MaxChunk = c.MinChunk
	}
	if c.MinDelay < 0 {
		c.MinDelay = 0
	}
	if c.MaxDelay < 0 {
		c.MaxDelay = 0
	}
	if c.MinDelay > c.MaxDelay {
		c.MinDelay = c.MaxDelay
	}
	return c
}

// Split slices data into segments of pseudo-random length within [min, max].
//
// The returned slices alias data — no copies, no allocation beyond the slice
// header array. A seeded *rand.Rand is taken explicitly so callers can make
// the split deterministic in tests.
func Split(data []byte, min, max int, rnd *rand.Rand) [][]byte {
	if len(data) == 0 {
		return nil
	}
	min, max = normalizeChunkBounds(min, max)
	segments := make([][]byte, 0, (len(data)/min)+1)
	for off := 0; off < len(data); {
		size := min
		if max > min && rnd != nil {
			size = min + rnd.Intn(max-min+1)
		}
		end := off + size
		if end > len(data) {
			end = len(data)
		}
		segments = append(segments, data[off:end])
		off = end
	}
	return segments
}

func normalizeChunkBounds(min, max int) (int, int) {
	if min < 1 {
		min = 1
	}
	if max < min {
		max = min
	}
	return min, max
}

// SplitAtSNIBoundary segments a ClientHello so an edge falls 3–12 bytes into
// its parsed hostname when a chunk-bounded partition can place it there. If
// parsing or bounds make that impossible, it behaves exactly like Split.
func SplitAtSNIBoundary(data []byte, min, max int, rnd *rand.Rand) [][]byte {
	if len(data) == 0 {
		return nil
	}
	min, max = normalizeChunkBounds(min, max)
	hostStart, hostEnd, ok := clientHelloSNIHostBounds(data)
	if !ok {
		return Split(data, min, max, rnd)
	}

	type boundary struct {
		target int
		prior  []int
	}
	var candidates []boundary
	for offset := 3; offset <= 12 && hostStart+offset <= hostEnd; offset++ {
		target := hostStart + offset
		candidate := boundary{target: target}
		firstPrior := target - max
		if firstPrior < 0 {
			firstPrior = 0
		}
		lastPrior := target - min
		if lastPrior > hostStart {
			lastPrior = hostStart
		}
		for prior := firstPrior; prior <= lastPrior; prior++ {
			if chunkLengthPartitionable(prior, min, max) {
				candidate.prior = append(candidate.prior, prior)
			}
		}
		if len(candidate.prior) > 0 {
			candidates = append(candidates, candidate)
		}
	}
	if len(candidates) == 0 {
		return Split(data, min, max, rnd)
	}

	chosen := candidates[0]
	if rnd != nil && len(candidates) > 1 {
		chosen = candidates[rnd.Intn(len(candidates))]
	}
	prior := chosen.prior[0]
	if rnd != nil && len(chosen.prior) > 1 {
		prior = chosen.prior[rnd.Intn(len(chosen.prior))]
	}

	segments := make([][]byte, 0, len(data)/min+2)
	off := 0
	for _, size := range partitionChunkLengths(prior, min, max, rnd) {
		segments = append(segments, data[off:off+size])
		off += size
	}
	segments = append(segments, data[prior:chosen.target])
	return append(segments, Split(data[chosen.target:], min, max, rnd)...)
}

func chunkLengthPartitionable(length, min, max int) bool {
	if length == 0 {
		return true
	}
	return (length+max-1)/max <= length/min
}

func partitionChunkLengths(length, min, max int, rnd *rand.Rand) []int {
	if length == 0 {
		return nil
	}
	minCount := (length + max - 1) / max
	maxCount := length / min
	count := minCount
	if rnd != nil && maxCount > minCount {
		count += rnd.Intn(maxCount - minCount + 1)
	}

	lengths := make([]int, count)
	for i := range lengths {
		lengths[i] = min
	}
	extra := length - count*min
	capacity := max - min
	for i := range lengths {
		remaining := len(lengths) - i - 1
		lowest := extra - remaining*capacity
		if lowest < 0 {
			lowest = 0
		}
		highest := extra
		if highest > capacity {
			highest = capacity
		}
		add := lowest
		if rnd != nil && highest > lowest {
			add += rnd.Intn(highest - lowest + 1)
		}
		lengths[i] += add
		extra -= add
	}
	return lengths
}

// SegmentCount reports how many writes Split would produce, without
// allocating. Useful for sizing and for asserting on policy in tests.
func SegmentCount(length, min, max int) int {
	if length <= 0 {
		return 0
	}
	if min < 1 {
		min = 1
	}
	if max < min {
		max = min
	}
	return (length + min - 1) / min
}

// DelayFor returns a delay in [MinDelay, MaxDelay] for the given source.
func (c Config) DelayFor(rnd *rand.Rand) time.Duration {
	if c.MaxDelay <= 0 {
		return 0
	}
	if c.MinDelay >= c.MaxDelay || rnd == nil {
		return c.MinDelay
	}
	span := int64(c.MaxDelay - c.MinDelay)
	return c.MinDelay + time.Duration(rnd.Int63n(span+1))
}

// flusher is satisfied by *bufio.Writer; a flush per segment is what pushes
// each chunk onto the wire as its own segment.
type flusher interface{ Flush() error }

// WriteFragmented writes data in configured segments with configured pauses.
//
// The first segment is written immediately — the delay applies *between*
// segments, because delaying the opening write only adds latency without
// changing how the stream is segmented.
func WriteFragmented(w io.Writer, data []byte, cfg Config, rnd *rand.Rand) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}

	var segments [][]byte
	if cfg.Fragments {
		segments = Split(data, cfg.MinChunk, cfg.MaxChunk, rnd)
	} else {
		segments = [][]byte{data}
	}
	return writeSegments(w, segments, cfg, rnd)
}

func writeSegments(w io.Writer, segments [][]byte, cfg Config, rnd *rand.Rand) (int, error) {
	written := 0
	for i, seg := range segments {
		if i > 0 {
			if d := cfg.DelayFor(rnd); d > 0 {
				time.Sleep(d)
			}
		}
		n, err := w.Write(seg)
		written += n
		if err != nil {
			return written, fmt.Errorf("dialer: write segment %d/%d: %w", i+1, len(segments), err)
		}
		if f, ok := w.(flusher); ok {
			if err := f.Flush(); err != nil {
				return written, fmt.Errorf("dialer: flush segment %d/%d: %w", i+1, len(segments), err)
			}
		}
	}
	return written, nil
}

// WriteHello applies SNI rewriting and then segmented transmission to one
// ClientHello. It is the entry point the connection path calls.
//
// A hello with no SNI extension is not an error: there is no name to spoof, so
// the bytes go out unchanged.
func WriteHello(w io.Writer, hello []byte, cfg Config, rnd *rand.Rand) (int, error) {
	payload := hello
	if cfg.FakeSNI != "" {
		rewritten, err := RewriteSNI(hello, cfg.FakeSNI)
		switch {
		case err == nil:
			payload = rewritten
		case errors.Is(err, ErrNoSNIExtension):
			// Nothing to rewrite; send as-is.
		default:
			return 0, fmt.Errorf("dialer: rewrite SNI: %w", err)
		}
	}
	if !cfg.Fragments {
		return WriteFragmented(w, payload, cfg, rnd)
	}
	return writeSegments(w, SplitAtSNIBoundary(payload, cfg.MinChunk, cfg.MaxChunk, rnd), cfg, rnd)
}
