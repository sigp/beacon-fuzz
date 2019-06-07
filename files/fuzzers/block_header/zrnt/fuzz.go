package fuzz

import (
	"github.com/protolambda/zrnt/eth2/beacon/block_processing"
    "helper"
)

func init() {
    helper.SetInputType(helper.INPUT_TYPE_BLOCK_HEADER)
}

func Fuzz(data []byte) []byte {
    input, err := helper.DecodeBlockHeader(data, false)
    if err != nil {
        return []byte{}
    }

    if err := block_processing.ProcessBlockHeader(&input.Pre, &input.Block); err != nil {
        return []byte{}
    }

    return helper.EncodePoststate(input.Pre)
}
/*
    TODO set PreviousBlockRoot in preprocessing
    input.Block.PreviousBlockRoot = zrnt_ssz.SigningRoot(input.Pre.LatestBlockHeader)
*/
