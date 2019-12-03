package fuzz

import (
	"github.com/cespare/xxhash"
	"github.com/protolambda/zrnt/eth2/phase0"
	"helper"
)

// TODO(gnattishness) allow configurable at compile time
const VALIDATE_STATE_ROOT bool = true

func xxhash256(input []byte) [32]byte {
	var ret [32]byte
	hash := xxhash.Sum64(input)
	ret[0] = byte(hash & 0xFF)
	ret[1] = byte(hash>>8) & 0xFF
	ret[2] = byte(hash>>16) & 0xFF
	ret[3] = byte(hash>>24) & 0xFF
	ret[4] = byte(hash>>32) & 0xFF
	ret[5] = byte(hash>>40) & 0xFF
	ret[6] = byte(hash>>48) & 0xFF
	ret[7] = byte(hash>>56) & 0xFF
	return ret
}

func init() {
	helper.SetInputType(helper.INPUT_TYPE_BLOCK)

	/* Uncomment once PySpec can use xxhash */
	/*
	   ssz.InitZeroHashes(xxhash256)
	   hashing.Hash = xxhash256
	   hashing.GetHashFn = func() hashing.HashFn {
	       return xxhash256
	   }
	*/
}

func Fuzz(data []byte) []byte {
	// TODO set fuzz to true here? or no, to keep consistent decoding
	input, err := helper.DecodeBlock(data, false)
	if err != nil {
		// A sanity check to ensure preprocessing works
		// Assumes preprocessing ensures data is decodable
		panic("Decoding failed - bug in preprocessing.")
	}
	ffstate := phase0.NewFullFeaturedState(&input.Pre)
	ffstate.LoadPrecomputedData()
	blockProc := new(phase0.BlockProcessFeature)
	blockProc.Meta = ffstate
	blockProc.Block = &input.Block
	if err := ffstate.StateTransition(blockProc, VALIDATE_STATE_ROOT); err != nil {
		return []byte{}
	}

	// NOTE this will panic if the invariants aren't correct
	return helper.EncodePoststate(ffstate.BeaconState)
	// equiv to
	// return helper.EncodePoststate(&input.Pre)
}
