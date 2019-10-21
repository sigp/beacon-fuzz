package fuzz

import (
	"github.com/protolambda/zrnt/eth2/phase0"
	"helper"
)

func init() {
	helper.SetInputType(helper.INPUT_TYPE_BLOCK_HEADER)
}

func Fuzz(data []byte) (result []byte) {
	input, err := helper.DecodeBlockHeader(data, false)
	if err != nil {
		// Assumes preprocessing ensures data is decodable
		panic("Decoding failed - bug in preprocessing.")
	}
	ffstate := phase0.NewFullFeaturedState(&input.Pre)
	ffstate.LoadPrecomputedData()
	blockHeader := (&input.Block).Header()

	if err := ffstate.ProcessHeader(blockHeader); err != nil {
		return []byte{}
	}

	return helper.EncodePoststate(ffstate.BeaconState)
}
