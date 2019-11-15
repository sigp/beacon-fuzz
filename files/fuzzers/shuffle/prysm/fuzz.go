package fuzz

import (
	"encoding/binary"
	"github.com/prysmaticlabs/prysm/beacon-chain/core/helpers"
)

func Fuzz(data []byte) []byte {
	if len(data) < 32+2 {
		return []byte{}
	}

	count := int(binary.LittleEndian.Uint16(data[:2])) % 100
	var seed [32]byte
	copy(seed[:], data[2:34])

	input := make([]uint64, count)
	for i := 0; i < count; i++ {
		input[i] = helpers.ValidatorIndex(i)
	}

        // TODO is this ShuffleList or UnshuffleList for prysm?
	input, err:= helpers.ShuffleList(input, seed)
	if err != nil {
		panic("Unshuffling failed with: %v", err)
	}

	ret := make([]byte, count*8)
	for i := 0; i < count; i++ {
		binary.LittleEndian.PutUint64(ret[i*8:], uint64(input[i]))
	}

	return ret
}
