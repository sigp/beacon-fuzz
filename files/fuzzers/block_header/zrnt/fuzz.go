package fuzz

import (
    "github.com/protolambda/zrnt/eth2/phase0"
    "helper"
)

func init() {
    helper.SetInputType(helper.INPUT_TYPE_BLOCK_HEADER)
}

// Doesn't look like this makes use of the PreState files?
func Fuzz(data []byte) []byte {
    input, err := helper.DecodeBlockHeader(data, false)
    if err != nil {
        return []byte{}
    }
    // Not needed if we make the Decode return a FullFeaturedState
    // Might want to use phase0.InitState instead?
    ffstate := phase0.NewFullFeaturedState(&input.Pre)
    blockHeader := (&input.Block).Header()

    if err := ffstate.BlockHeaderFeature.ProcessHeader(blockHeader); err != nil {
        return []byte{}
    }

    return helper.EncodePoststate(input.Pre)
}
/*
    TODO set PreviousBlockRoot in preprocessing
    input.Block.PreviousBlockRoot = zrnt_ssz.SigningRoot(input.Pre.LatestBlockHeader)
*/
