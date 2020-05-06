package fuzz

import (
	"helper"

	"github.com/protolambda/zrnt/eth2/phase0"
)

func init() {
	helper.SetInputType(helper.INPUT_TYPE_PROPOSER_SLASHING)
}

func Fuzz(data []byte) ([]byte, error) {
	input, err := helper.DecodeProposerSlashing(data, false)
	if err != nil {
		panic("Decoding failed - bug in preprocessing.")
	}
	ffstate := phase0.NewFullFeaturedState(&input.Pre)
	ffstate.LoadPrecomputedData()

	if err := ffstate.ProcessProposerSlashing(&input.ProposerSlashing); err != nil {
		return []byte{}, err
	}

	return helper.EncodePoststate(ffstate.BeaconState), nil
}
