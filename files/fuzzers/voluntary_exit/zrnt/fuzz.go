package fuzz

import (
	"helper"

	"github.com/protolambda/zrnt/eth2/phase0"
)

func init() {
	helper.SetInputType(helper.INPUT_TYPE_VOLUNTARY_EXIT)
}

func Fuzz(data []byte) []byte {
	input, err := helper.DecodeVoluntaryExit(data, false)
	if err != nil {
		panic("Decoding failed - bug in preprocessing.")
	}
	ffstate := phase0.NewFullFeaturedState(&input.Pre)
	ffstate.LoadPrecomputedData()

	if err := ffstate.ProcessVoluntaryExit(&input.Exit); err != nil {
		return []byte{}
	}

	return helper.EncodePoststate(ffstate.BeaconState)
}
