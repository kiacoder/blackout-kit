package dialer

import (
	"bytes"
	"errors"
	"math/rand"
	"testing"
	"time"
)

// recordingWriter captures each Write as a separate segment so tests can assert
// on how the stream was chopped up — which is the entire point of the package.
type recordingWriter struct {
	segments [][]byte
	at       []time.Time
}

func (w *recordingWriter) Write(p []byte) (int, error) {
	cp := append([]byte(nil), p...)
	w.segments = append(w.segments, cp)
	w.at = append(w.at, time.Now())
	return len(p), nil
}

func (w *recordingWriter) joined() []byte {
	var out []byte
	for _, s := range w.segments {
		out = append(out, s...)
	}
	return out
}

func TestSplitCoversAllBytes(t *testing.T) {
	data := bytes.Repeat([]byte("abcdefghij"), 40) // 400 bytes
	rnd := rand.New(rand.NewSource(1))

	for _, bounds := range [][2]int{{1, 1}, {8, 24}, {1, 64}, {400, 400}, {1000, 1000}} {
		segments := Split(data, bounds[0], bounds[1], rnd)
		var got []byte
		for _, s := range segments {
			got = append(got, s...)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("bounds %v: reassembled bytes differ from input", bounds)
		}
	}
}

func TestSplitAtSNIBoundaryPlacesSeededEdgeInsideHostname(t *testing.T) {
	const host = "blocked.example.com"
	hello := buildHello(t, host, true)
	hostStart := bytes.Index(hello, []byte(host))
	if hostStart < 0 {
		t.Fatal("fixture does not contain its hostname")
	}

	seenOffsets := make(map[int]bool)
	for seed := int64(1); seed <= 30; seed++ {
		segments := SplitAtSNIBoundary(hello, 8, 24, rand.New(rand.NewSource(seed)))
		var joined []byte
		boundary := -1
		for _, segment := range segments {
			joined = append(joined, segment...)
			if boundary < 0 && len(joined) > hostStart {
				boundary = len(joined)
			}
		}
		if !bytes.Equal(joined, hello) {
			t.Fatalf("seed %d: reassembled bytes differ from ClientHello", seed)
		}
		if boundary < hostStart+3 || boundary > hostStart+12 {
			t.Fatalf("seed %d: first edge after hostname start is at %d, want %d..%d", seed, boundary, hostStart+3, hostStart+12)
		}
		seenOffsets[boundary-hostStart] = true
	}
	if len(seenOffsets) < 2 {
		t.Fatalf("seeded helper chose only one hostname offset: %v", seenOffsets)
	}

	first := SplitAtSNIBoundary(hello, 8, 24, rand.New(rand.NewSource(17)))
	replay := SplitAtSNIBoundary(hello, 8, 24, rand.New(rand.NewSource(17)))
	if len(first) != len(replay) {
		t.Fatalf("same seed produced %d and %d segments", len(first), len(replay))
	}
	for i := range first {
		if !bytes.Equal(first[i], replay[i]) {
			t.Fatalf("same seed produced different segment %d", i)
		}
	}
}

func TestSplitAtSNIBoundaryFallsBackWithoutValidParsedPartition(t *testing.T) {
	withSNI := buildHello(t, "blocked.example.com", true)
	withoutSNI := buildHello(t, "", false)
	cases := []struct {
		name string
		data []byte
		min  int
		max  int
	}{
		{name: "no feasible SNI partition", data: withSNI, min: 30, max: 30},
		{name: "no SNI extension", data: withoutSNI, min: 8, max: 24},
		{name: "malformed ClientHello", data: []byte{recordTypeHandshake, 0x03}, min: 8, max: 24},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SplitAtSNIBoundary(tc.data, tc.min, tc.max, rand.New(rand.NewSource(23)))
			want := Split(tc.data, tc.min, tc.max, rand.New(rand.NewSource(23)))
			if len(got) != len(want) {
				t.Fatalf("got %d segments, fallback produced %d", len(got), len(want))
			}
			for i := range want {
				if !bytes.Equal(got[i], want[i]) {
					t.Fatalf("segment %d differs from existing split fallback", i)
				}
			}
		})
	}
}

func TestWriteHelloSegmentsInsideParsedSNIHostname(t *testing.T) {
	const host = "blocked.example.com"
	hello := buildHello(t, host, true)
	hostStart := bytes.Index(hello, []byte(host))
	cfg := DefaultConfig()
	cfg.MinChunk, cfg.MaxChunk = 8, 24
	cfg.MinDelay, cfg.MaxDelay = 0, 0

	writer := &recordingWriter{}
	if n, err := WriteHello(writer, hello, cfg, rand.New(rand.NewSource(17))); err != nil {
		t.Fatalf("WriteHello: %v", err)
	} else if n != len(hello) {
		t.Fatalf("WriteHello wrote %d bytes, want %d", n, len(hello))
	}
	if !bytes.Equal(writer.joined(), hello) {
		t.Fatal("WriteHello changed ClientHello bytes while segmenting")
	}

	boundary := -1
	written := 0
	for _, segment := range writer.segments {
		written += len(segment)
		if written > hostStart {
			boundary = written
			break
		}
	}
	if boundary < hostStart+3 || boundary > hostStart+12 {
		t.Fatalf("WriteHello edge is at %d, want %d..%d bytes into hostname", boundary, hostStart+3, hostStart+12)
	}
}

// TestSplitRespectsBounds is the Bug #11 assertion: segment size is bounded by
// config, never hardcoded.
func TestSplitRespectsBounds(t *testing.T) {
	data := bytes.Repeat([]byte("x"), 500)
	rnd := rand.New(rand.NewSource(7))

	segments := Split(data, 8, 24, rnd)
	if len(segments) == 0 {
		t.Fatal("no segments produced")
	}
	for i, s := range segments {
		if len(s) < 1 {
			t.Fatalf("segment %d is empty", i)
		}
		if len(s) > 24 {
			t.Fatalf("segment %d is %d bytes, over max_chunk 24", i, len(s))
		}
	}
	// Every segment but the last should sit in [8, 24].
	for i := 0; i < len(segments)-1; i++ {
		if n := len(segments[i]); n < 8 || n > 24 {
			t.Fatalf("segment %d is %d bytes, want 8..24", i, n)
		}
	}
	// Bounds must actually change the outcome.
	fine := Split(data, 1, 2, rand.New(rand.NewSource(7)))
	coarse := Split(data, 100, 200, rand.New(rand.NewSource(7)))
	if len(fine) <= len(coarse) {
		t.Fatalf("finer bounds produced %d segments, coarser %d — bounds have no effect", len(fine), len(coarse))
	}
}

func TestSplitEmptyAndNilRand(t *testing.T) {
	if got := Split(nil, 8, 24, rand.New(rand.NewSource(1))); got != nil {
		t.Fatalf("Split(nil) = %v, want nil", got)
	}
	// A nil RNG must not panic; it degrades to fixed-size segments.
	segments := Split(bytes.Repeat([]byte("z"), 20), 5, 10, nil)
	if len(segments) != 4 {
		t.Fatalf("nil-rand split produced %d segments, want 4", len(segments))
	}
}

func TestSegmentCount(t *testing.T) {
	if got := SegmentCount(100, 8, 24); got != 13 {
		t.Fatalf("SegmentCount(100,8,24) = %d, want 13", got)
	}
	if got := SegmentCount(0, 8, 24); got != 0 {
		t.Fatalf("SegmentCount(0,...) = %d, want 0", got)
	}
}

func TestWriteFragmentedSegmentCount(t *testing.T) {
	data := bytes.Repeat([]byte("payload"), 20) // 140 bytes
	cfg := DefaultConfig()
	cfg.MinChunk, cfg.MaxChunk = 10, 10
	cfg.MinDelay, cfg.MaxDelay = 0, 0

	w := &recordingWriter{}
	n, err := WriteFragmented(w, data, cfg, rand.New(rand.NewSource(3)))
	if err != nil {
		t.Fatalf("WriteFragmented: %v", err)
	}
	if n != len(data) {
		t.Fatalf("wrote %d bytes, want %d", n, len(data))
	}
	if len(w.segments) != 14 {
		t.Fatalf("produced %d segments, want 14", len(w.segments))
	}
	if !bytes.Equal(w.joined(), data) {
		t.Fatal("reassembled payload differs from input")
	}
}

func TestWriteFragmentedDisabled(t *testing.T) {
	data := bytes.Repeat([]byte("payload"), 20)
	cfg := DefaultConfig()
	cfg.Fragments = false
	cfg.MinChunk, cfg.MaxChunk = 1, 1

	w := &recordingWriter{}
	if _, err := WriteFragmented(w, data, cfg, rand.New(rand.NewSource(3))); err != nil {
		t.Fatalf("WriteFragmented: %v", err)
	}
	if len(w.segments) != 1 {
		t.Fatalf("fragments disabled but got %d writes, want 1", len(w.segments))
	}
}

// TestWriteFragmentedAppliesDelay is the other half of Bug #11. Segmentation
// alone is invisible if the kernel coalesces the writes back together; the
// inter-segment pause is what forces them onto the wire as distinct segments.
func TestWriteFragmentedAppliesDelay(t *testing.T) {
	data := bytes.Repeat([]byte("p"), 6)
	cfg := DefaultConfig()
	cfg.MinChunk, cfg.MaxChunk = 1, 1
	cfg.MinDelay, cfg.MaxDelay = 200*time.Microsecond, 200*time.Microsecond

	w := &recordingWriter{}
	start := time.Now()
	if _, err := WriteFragmented(w, data, cfg, rand.New(rand.NewSource(3))); err != nil {
		t.Fatalf("WriteFragmented: %v", err)
	}
	elapsed := time.Since(start)

	if len(w.segments) != 6 {
		t.Fatalf("got %d segments, want 6", len(w.segments))
	}
	// 5 gaps at 200us each; allow for scheduler slack on a loaded CI box.
	want := 5 * 200 * time.Microsecond
	if elapsed < want/2 {
		t.Fatalf("elapsed %v, expected at least ~%v of deliberate delay", elapsed, want)
	}
}

func TestDelayForBounds(t *testing.T) {
	cfg := Config{MinDelay: 100 * time.Microsecond, MaxDelay: 500 * time.Microsecond}
	rnd := rand.New(rand.NewSource(11))
	for i := 0; i < 200; i++ {
		d := cfg.DelayFor(rnd)
		if d < cfg.MinDelay || d > cfg.MaxDelay {
			t.Fatalf("delay %v outside [%v, %v]", d, cfg.MinDelay, cfg.MaxDelay)
		}
	}
	if got := (Config{MinDelay: 0, MaxDelay: 0}).DelayFor(rnd); got != 0 {
		t.Fatalf("zero config produced %v delay", got)
	}
}

func TestConfigValidateAndNormalize(t *testing.T) {
	if err := DefaultConfig().Validate(); err != nil {
		t.Fatalf("DefaultConfig invalid: %v", err)
	}
	if err := (Config{MinChunk: 0, MaxChunk: 10}).Validate(); !errors.Is(err, ErrBadChunkRange) {
		t.Fatalf("min<1: err = %v, want ErrBadChunkRange", err)
	}
	if err := (Config{MinChunk: 20, MaxChunk: 10}).Validate(); !errors.Is(err, ErrBadChunkRange) {
		t.Fatalf("max<min: err = %v, want ErrBadChunkRange", err)
	}

	// Normalize must produce something valid rather than failing: a bad tune
	// value arriving over IPC must not take the engine down.
	n := (Config{MinChunk: 0, MaxChunk: 5, MinDelay: time.Second, MaxDelay: time.Millisecond}).Normalize()
	if err := n.Validate(); err != nil {
		t.Fatalf("normalized config still invalid: %v", err)
	}
	if n.MinChunk != 1 {
		t.Fatalf("MinChunk normalized to %d, want 1", n.MinChunk)
	}
	if n.MinDelay > n.MaxDelay {
		t.Fatalf("delays not clamped: %v > %v", n.MinDelay, n.MaxDelay)
	}
}

// TestWriteHelloRewritesSNI ties the two halves together: the SNI substitution
// and the segmentation both have to happen on the same outbound path, which is
// exactly what v1's sni.go failed to do.
func TestWriteHelloRewritesSNI(t *testing.T) {
	hello := buildHello(t, "blocked.example.com", true)
	const fake = "www.microsoft.com"

	cfg := DefaultConfig()
	cfg.FakeSNI = fake
	cfg.MinChunk, cfg.MaxChunk = 16, 32
	cfg.MinDelay, cfg.MaxDelay = 0, 0

	w := &recordingWriter{}
	if _, err := WriteHello(w, hello, cfg, rand.New(rand.NewSource(5))); err != nil {
		t.Fatalf("WriteHello: %v", err)
	}

	payload := w.joined()
	got, err := ExtractSNI(payload)
	if err != nil {
		t.Fatalf("ExtractSNI on transmitted bytes: %v", err)
	}
	if got != fake {
		t.Fatalf("transmitted SNI = %q, want %q", got, fake)
	}
	if len(w.segments) < 2 {
		t.Fatalf("expected the hello to be split, got %d write(s)", len(w.segments))
	}
}

func TestWriteHelloWithoutSNIConfig(t *testing.T) {
	hello := buildHello(t, "blocked.example.com", true)
	cfg := DefaultConfig()
	cfg.MinDelay, cfg.MaxDelay = 0, 0

	w := &recordingWriter{}
	if _, err := WriteHello(w, hello, cfg, rand.New(rand.NewSource(5))); err != nil {
		t.Fatalf("WriteHello: %v", err)
	}
	got, err := ExtractSNI(w.joined())
	if err != nil {
		t.Fatalf("ExtractSNI: %v", err)
	}
	if got != "blocked.example.com" {
		t.Fatalf("SNI = %q, want it left alone when FakeSNI is empty", got)
	}
}

// TestWriteHelloNoSNIExtensionIsNotFatal covers a hello that predates SNI:
// there is nothing to spoof, so the bytes must go out unchanged rather than
// dropping the connection.
func TestWriteHelloNoSNIExtensionIsNotFatal(t *testing.T) {
	hello := buildHello(t, "", false)
	cfg := DefaultConfig()
	cfg.FakeSNI = "www.microsoft.com"
	cfg.MinDelay, cfg.MaxDelay = 0, 0

	w := &recordingWriter{}
	if _, err := WriteHello(w, hello, cfg, rand.New(rand.NewSource(5))); err != nil {
		t.Fatalf("WriteHello should tolerate a hello without SNI: %v", err)
	}
	if !bytes.Equal(w.joined(), hello) {
		t.Fatal("hello without SNI should be passed through unchanged")
	}
}
