package fuzz

import (
	"encoding/binary"
	"fmt"

	"github.com/protolambda/zrnt/eth2/core"
	"github.com/protolambda/zrnt/eth2/util/shuffle"
)

func Fuzz(data []byte) ([]byte, error) {
	if len(data) < 32+2 {
		return []byte{}, fmt.Errorf("not enough data provided: only %v bytes, expected at least 34", len(data))
	}

	count := int(binary.LittleEndian.Uint16(data[:2])) % 100
	var seed [32]byte
	copy(seed[:], data[2:34])

	input := make([]core.ValidatorIndex, count)
	for i := 0; i < count; i++ {
		input[i] = core.ValidatorIndex(i)
	}

	shuffle.UnshuffleList(input, seed)

	ret := make([]byte, count*8)
	for i := 0; i < count; i++ {
		binary.LittleEndian.PutUint64(ret[i*8:], uint64(input[i]))
	}

	return ret, nil
}
