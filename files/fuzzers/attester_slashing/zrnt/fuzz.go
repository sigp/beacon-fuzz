package fuzz

import (
	"github.com/protolambda/zrnt/eth2/phase0"
	"helper"
)

func init() {
	helper.SetInputType(helper.INPUT_TYPE_ATTESTER_SLASHING)
}

func Fuzz(data []byte) []byte {
	input, err := helper.DecodeAttesterSlashing(data, false)
	if err != nil {
		panic("Decoding failed - bug in preprocessing.")
	}
	ffstate := phase0.NewFullFeaturedState(&input.Pre)
	ffstate.LoadPrecomputedData()

	if err := ffstate.ProcessAttesterSlashing(&input.AttesterSlashing); err != nil {
		return []byte{}
	}

	return helper.EncodePoststate(&input.Pre)
}
