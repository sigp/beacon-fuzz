package fuzz

import (
	"github.com/protolambda/zrnt/eth2/beacon/block_processing"
	"helper"
)

func init() {
	helper.SetInputType(helper.INPUT_TYPE_PROPOSER_SLASHING)
}

func Fuzz(data []byte) []byte {
	input, err := helper.DecodeProposerSlashing(data, false)
	if err != nil {
		return []byte{}
	}

	if err := block_processing.ProcessProposerSlashing(&input.Pre, &input.ProposerSlashing); err != nil {
		return []byte{}
	}

	return helper.EncodePoststate(input.Pre)
}
