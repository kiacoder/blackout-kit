package hyperpulse

import (
	"bytes"
	"reflect"
	"testing"
	"time"
)

func TestGF256VectorsUsePolynomial11D(t *testing.T) {
	if got := gfMul(0x02, 0x80); got != 0x1d {
		t.Fatalf("gfMul(0x02, 0x80) = %#02x, want %#02x", got, 0x1d)
	}
	if got := gfInv(0x02); got != 0x8e {
		t.Fatalf("gfInv(0x02) = %#02x, want %#02x", got, 0x8e)
	}
	if got := gfAdd(0x53, 0xca); got != 0x99 {
		t.Fatalf("gfAdd(0x53, 0xca) = %#02x, want XOR result %#02x", got, 0x99)
	}
}

func TestEncodeProducesFixedSystematicParityVector(t *testing.T) {
	data := [][]byte{{0x01, 0x02}, {0x02, 0x03}}
	got, err := Encode(data, 1)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	want := [][]byte{{0x03, 0x01}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Encode parity = % x, want % x", got, want)
	}
}

func TestEncodeRejectsInvalidSourceShards(t *testing.T) {
	cases := []struct {
		name        string
		data        [][]byte
		parityCount int
	}{
		{name: "no data"},
		{name: "empty shard", data: [][]byte{{}}},
		{name: "unequal shard lengths", data: [][]byte{{1}, {2, 3}}},
		{name: "negative parity count", data: [][]byte{{1}}, parityCount: -1},
		{name: "too many field elements", data: makeShards(256, 1), parityCount: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Encode(tc.data, tc.parityCount); err == nil {
				t.Fatal("Encode succeeded for invalid input")
			}
		})
	}
}

func TestRecoverReconstructsOneMissingShard(t *testing.T) {
	data := testSourceShards()
	want := cloneShards(data)
	parity, err := Encode(data, 2)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	known := cloneShards(data)
	known[1] = nil

	got, err := Recover(known, parity[:1], []int{1})
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if !reflect.DeepEqual(got, [][]byte{want[1]}) {
		t.Fatalf("recovered shards = % x, want % x", got, [][]byte{want[1]})
	}
	if !reflect.DeepEqual(known[0], want[0]) || !reflect.DeepEqual(known[2], want[2]) {
		t.Fatal("Recover mutated a known source shard")
	}
}

func TestRecoverReconstructsMultipleMissingShardsInRequestedOrder(t *testing.T) {
	data := testSourceShards()
	want := cloneShards(data)
	parity, err := Encode(data, 2)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	known := cloneShards(data)
	known[0], known[2] = nil, nil

	got, err := Recover(known, parity, []int{2, 0})
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if !reflect.DeepEqual(got, [][]byte{want[2], want[0]}) {
		t.Fatalf("recovered shards = % x, want % x", got, [][]byte{want[2], want[0]})
	}
	if !reflect.DeepEqual(known[1], want[1]) {
		t.Fatal("Recover mutated the known source shard")
	}
}

func TestRecoverRejectsMalformedShardsAndMissingIndices(t *testing.T) {
	goodData := testSourceShards()
	goodParity, err := Encode(goodData, 2)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	cases := []struct {
		name    string
		data    [][]byte
		parity  [][]byte
		missing []int
	}{
		{name: "missing index outside data", data: [][]byte{nil, {2, 3}}, parity: goodParity, missing: []int{2}},
		// valid source shards are required below except for listed missing slots
		{name: "duplicate missing index", data: [][]byte{nil, {2, 3}, {3, 4}}, parity: goodParity, missing: []int{0, 0}},
		{name: "missing slot is not nil", data: [][]byte{{1, 2}, {2, 3}, {3, 4}}, parity: goodParity, missing: []int{0}},
		{name: "known slot is nil", data: [][]byte{nil, nil, {3, 4}}, parity: goodParity, missing: []int{0}},
		{name: "insufficient parity", data: [][]byte{nil, nil, {3, 4}}, parity: goodParity[:1], missing: []int{0, 1}},
		{name: "unequal known shard length", data: [][]byte{nil, {2}, {3, 4}}, parity: goodParity, missing: []int{0}},
		{name: "unequal parity length", data: [][]byte{nil, {2, 3}, {3, 4}}, parity: [][]byte{goodParity[0], {1}}, missing: []int{0}},
		{name: "zero-length available shard", data: [][]byte{nil, {}}, parity: [][]byte{{}}, missing: []int{0}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Recover(tc.data, tc.parity, tc.missing); err == nil {
				t.Fatal("Recover succeeded for malformed input")
			}
		})
	}
}

func TestAdaptivePolicyUsesBoundedSlidingWindowMeasurements(t *testing.T) {
	policy := AdaptivePolicy{MinParity: 1, MaxParity: 5, WindowSize: 2}
	if got := policy.Observe(20*time.Millisecond, 0, 100); got != 1 {
		t.Fatalf("healthy sample parity = %d, want min 1", got)
	}
	if got := policy.Observe(20*time.Millisecond, 0, 100); got != 1 {
		t.Fatalf("stable window parity = %d, want min 1", got)
	}
	if got := policy.Observe(20*time.Millisecond, 50, 100); got != 2 {
		t.Fatalf("25%% aggregate drop window parity = %d, want 2", got)
	}
	if got := policy.Observe(20*time.Millisecond, 0, 100); got != 2 {
		t.Fatalf("window retaining 25%% drops parity = %d, want 2", got)
	}
	if got := policy.Observe(20*time.Millisecond, 0, 100); got != 1 {
		t.Fatalf("window after old loss expires parity = %d, want min 1", got)
	}
	if got := policy.Observe(100*time.Millisecond, 0, 100); got != 3 {
		t.Fatalf("high RTT variation parity = %d, want 3", got)
	}
}

func TestAdaptivePolicyCapsOversizedWindow(t *testing.T) {
	policy := AdaptivePolicy{MinParity: 0, MaxParity: 1, WindowSize: 1 << 30}
	if got := policy.Observe(0, 0, 1); got != 0 {
		t.Fatalf("oversized window sample parity = %d, want 0", got)
	}
	if len(policy.samples) > maxPolicyWindow {
		t.Fatalf("allocated %d samples, max policy window is %d", len(policy.samples), maxPolicyWindow)
	}
}

func TestAdaptivePolicyKeepsParityWithinExtremeCallerLimits(t *testing.T) {
	maxInt := int(^uint(0) >> 1)
	policy := AdaptivePolicy{MinParity: 0, MaxParity: maxInt, WindowSize: 1}
	if got := policy.Observe(time.Millisecond, 10, 10); got != maxInt {
		t.Fatalf("maximum loss parity = %d, want max %d", got, maxInt)
	}
}

func TestAdaptivePolicyDropRateDoesNotOverflowWindowTotals(t *testing.T) {
	policy := AdaptivePolicy{MinParity: 1, MaxParity: 5, WindowSize: 2}
	maxUint := ^uint64(0)
	policy.Observe(20*time.Millisecond, maxUint/2+1, maxUint/2+1)
	if got := policy.Observe(20*time.Millisecond, maxUint/2+1, maxUint/2+1); got != 5 {
		t.Fatalf("100%% aggregate loss parity = %d, want 5", got)
	}

	policy = AdaptivePolicy{MinParity: 1, MaxParity: 5, WindowSize: 2}
	policy.Observe(20*time.Millisecond, maxUint/2+1, maxUint/2+1)
	if got := policy.Observe(20*time.Millisecond, 0, maxUint/2+1); got != 3 {
		t.Fatalf("50%% aggregate loss parity = %d, want 3", got)
	}
}

func TestAdaptivePolicyClampsLimitsAndMeasurements(t *testing.T) {
	policy := AdaptivePolicy{MinParity: -3, MaxParity: 2, WindowSize: 1}
	if got := policy.Observe(0, 10, 10); got != 2 {
		t.Fatalf("clamped high-loss sample parity = %d, want max 2", got)
	}
	policy = AdaptivePolicy{MinParity: 4, MaxParity: 2, WindowSize: 0}
	if got := policy.Observe(-time.Millisecond, 1, 1); got != 4 {
		t.Fatalf("inverted limits parity = %d, want normalized minimum 4", got)
	}
}

func testSourceShards() [][]byte {
	return [][]byte{{0x01, 0x02, 0x03}, {0x11, 0x12, 0x13}, {0x21, 0x22, 0x23}}
}

func cloneShards(shards [][]byte) [][]byte {
	out := make([][]byte, len(shards))
	for i, shard := range shards {
		out[i] = bytes.Clone(shard)
	}
	return out
}

func makeShards(count, size int) [][]byte {
	shards := make([][]byte, count)
	for i := range shards {
		shards[i] = make([]byte, size)
	}
	return shards
}
