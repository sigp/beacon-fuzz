package fuzz

import (
	"github.com/protolambda/zrnt/eth2/beacon/block_processing"
    "helper"
)

func init() {
    helper.SetInputType(helper.INPUT_TYPE_ATTESTER_SLASHING)
}

func Fuzz(data []byte) []byte {
    input, err := helper.DecodeAttesterSlashing(data, false)
    if err != nil {
        return []byte{}
    }

    if err := block_processing.ProcessAttesterSlashing(&input.Pre, &input.AttesterSlashing); err != nil {
        return []byte{}
    }

    return helper.EncodePoststate(input.Pre)
}
