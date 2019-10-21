package fuzz

import (
	"github.com/protolambda/zrnt/eth2/beacon/block_processing"
	"helper"
)

func init() {
	helper.SetInputType(helper.INPUT_TYPE_TRANSFER)
}

func Fuzz(data []byte) []byte {
	input, err := helper.DecodeTransfer(data, false)
	if err != nil {
		return []byte{}
	}

	if err := block_processing.ProcessTransfer(&input.Pre, &input.Transfer); err != nil {
		return []byte{}
	}

	return helper.EncodePoststate(input.Pre)
}
