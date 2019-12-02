package fuzz

import (
	"github.com/protolambda/zrnt/eth2/beacon/block_processing"
	"helper"
)

func init() {
	helper.SetInputType(helper.INPUT_TYPE_VOLUNTARY_EXIT)
}

func Fuzz(data []byte) []byte {
	input, err := helper.DecodeVoluntaryExit(data, false)
	if err != nil {
		return []byte{}
	}

	if err := block_processing.ProcessVoluntaryExit(&input.Pre, &input.VoluntaryExit); err != nil {
		return []byte{}
	}

	return helper.EncodePoststate(input.Pre)
}
