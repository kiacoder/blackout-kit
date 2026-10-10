package hyperpulse

import (
	"errors"
	"fmt"
)

var (
	ErrInvalidData     = errors.New("hyperpulse: invalid data shards")
	ErrInvalidParity   = errors.New("hyperpulse: invalid parity shards")
	ErrInvalidMissing  = errors.New("hyperpulse: invalid missing indices")
	ErrInsufficientFEC = errors.New("hyperpulse: insufficient parity shards")
)

// Encode returns parity rows from a systematic Vandermonde generator matrix.
// The source shards remain unchanged; each row can recover one additional shard.
func Encode(data [][]byte, parityCount int) ([][]byte, error) {
	shardSize, err := validateSourceShards(data)
	if err != nil {
		return nil, err
	}
	if parityCount < 0 || parityCount > 256-len(data) {
		return nil, fmt.Errorf("%w: parity count %d outside supported range", ErrInvalidParity, parityCount)
	}
	parity := make([][]byte, parityCount)
	for row := 0; row < parityCount; row++ {
		parity[row] = make([]byte, shardSize)
		for col, shard := range data {
			coefficient := gfPow(byte(col), row)
			for i, value := range shard {
				parity[row][i] ^= gfMul(coefficient, value)
			}
		}
	}
	return parity, nil
}

// Recover reconstructs the requested source shards. data must retain its full
// source width, with nil at each missing index. Returned shards follow missing
// order; no known source shard or parity shard is modified.
func Recover(data [][]byte, parity [][]byte, missing []int) ([][]byte, error) {
	if len(data) == 0 || len(data) > 256 || len(missing) == 0 {
		return nil, ErrInvalidData
	}
	if len(missing) > len(parity) {
		return nil, ErrInsufficientFEC
	}
	seen := make([]bool, len(data))
	for _, index := range missing {
		if index < 0 || index >= len(data) || seen[index] {
			return nil, fmt.Errorf("%w: index %d is out of range or repeated", ErrInvalidMissing, index)
		}
		seen[index] = true
		if data[index] != nil {
			return nil, fmt.Errorf("%w: missing source index %d is not nil", ErrInvalidMissing, index)
		}
	}

	shardSize := -1
	for i, shard := range data {
		if seen[i] {
			continue
		}
		if len(shard) == 0 {
			return nil, fmt.Errorf("%w: known shard %d is empty", ErrInvalidData, i)
		}
		if shardSize < 0 {
			shardSize = len(shard)
		} else if len(shard) != shardSize {
			return nil, fmt.Errorf("%w: shard %d has length %d, want %d", ErrInvalidData, i, len(shard), shardSize)
		}
	}
	if shardSize < 0 {
		if len(parity) == 0 || len(parity[0]) == 0 {
			return nil, fmt.Errorf("%w: cannot infer shard length", ErrInvalidData)
		}
		shardSize = len(parity[0])
	}
	if len(parity) < len(missing) {
		return nil, ErrInsufficientFEC
	}
	for i, shard := range parity {
		if len(shard) != shardSize {
			return nil, fmt.Errorf("%w: parity shard %d has length %d, want %d", ErrInvalidParity, i, len(shard), shardSize)
		}
	}

	// Use the first m available rows in encoded order to build an m-by-m
	// system for the missing source columns.
	unknowns := len(missing)
	matrix := make([][]byte, unknowns)
	rhs := make([][]byte, unknowns)
	for row := 0; row < unknowns; row++ {
		matrix[row] = make([]byte, unknowns)
		rhs[row] = append([]byte(nil), parity[row]...)
		for col, shard := range data {
			if seen[col] {
				continue
			}
			coefficient := gfPow(byte(col), row)
			for offset, value := range shard {
				rhs[row][offset] ^= gfMul(coefficient, value)
			}
		}
		for col, index := range missing {
			matrix[row][col] = gfPow(byte(index), row)
		}
	}
	if err := invertAndApply(matrix, rhs); err != nil {
		return nil, err
	}
	return rhs, nil
}

func validateSourceShards(data [][]byte) (int, error) {
	if len(data) == 0 || len(data) > 256 {
		return 0, fmt.Errorf("%w: source count must be between 1 and 256", ErrInvalidData)
	}
	if len(data[0]) == 0 {
		return 0, fmt.Errorf("%w: source shard 0 is empty", ErrInvalidData)
	}
	shardSize := len(data[0])
	for i, shard := range data {
		if len(shard) != shardSize {
			return 0, fmt.Errorf("%w: source shard %d has length %d, want %d", ErrInvalidData, i, len(shard), shardSize)
		}
	}
	return shardSize, nil
}

// invertAndApply performs Gaussian elimination on matrix while applying the
// identical row operations to rhs, which yields the unknown shard buffers.
func invertAndApply(matrix [][]byte, rhs [][]byte) error {
	n := len(matrix)
	for pivot := 0; pivot < n; pivot++ {
		selected := pivot
		for selected < n && matrix[selected][pivot] == 0 {
			selected++
		}
		if selected == n {
			return fmt.Errorf("%w: parity rows are not invertible for missing indices", ErrInvalidParity)
		}
		matrix[pivot], matrix[selected] = matrix[selected], matrix[pivot]
		rhs[pivot], rhs[selected] = rhs[selected], rhs[pivot]

		scale := gfInv(matrix[pivot][pivot])
		for col := pivot; col < n; col++ {
			matrix[pivot][col] = gfMul(matrix[pivot][col], scale)
		}
		for offset := range rhs[pivot] {
			rhs[pivot][offset] = gfMul(rhs[pivot][offset], scale)
		}

		for row := 0; row < n; row++ {
			if row == pivot || matrix[row][pivot] == 0 {
				continue
			}
			factor := matrix[row][pivot]
			for col := pivot; col < n; col++ {
				matrix[row][col] ^= gfMul(factor, matrix[pivot][col])
			}
			for offset := range rhs[row] {
				rhs[row][offset] ^= gfMul(factor, rhs[pivot][offset])
			}
		}
	}
	return nil
}
