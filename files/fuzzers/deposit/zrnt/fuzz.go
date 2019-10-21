package fuzz

import (
	"github.com/protolambda/zrnt/eth2/beacon/block_processing"
	"helper"
)

func init() {
	helper.SetInputType(helper.INPUT_TYPE_DEPOSIT)
}

func Fuzz(data []byte) []byte {
	input, err := helper.DecodeDeposit(data, false)
	if err != nil {
		return []byte{}
	}

	if err := block_processing.ProcessDeposit(&input.Pre, &input.Deposit); err != nil {
		return []byte{}
	}

	return helper.EncodePoststate(input.Pre)
}
