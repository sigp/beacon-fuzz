package fuzz

import (
	"helper"

	"github.com/protolambda/zrnt/eth2/phase0"
)

func init() {
	helper.SetInputType(helper.INPUT_TYPE_DEPOSIT)
}

func Fuzz(data []byte) []byte {
	input, err := helper.DecodeDeposit(data, false)
	if err != nil {
		panic("Decoding failed - bug in preprocessing.")
	}
	ffstate := phase0.NewFullFeaturedState(&input.Pre)
	ffstate.LoadPrecomputedData()

	if err := ffstate.ProcessDeposit(&input.Deposit); err != nil {
		return []byte{}
	}

	return helper.EncodePoststate(ffstate.BeaconState)
}
