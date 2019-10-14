package fuzz

import (
    "github.com/protolambda/zrnt/eth2/phase0"
    "helper"
    "fmt"
    "os"
)

func init() {
    helper.SetInputType(helper.INPUT_TYPE_BLOCK_HEADER)
}

// Doesn't look like this makes use of the PreState files?
func Fuzz(data []byte) (result []byte) {
    // TODO remove
    // helpers should never panic?
    input, err := helper.DecodeBlockHeader(data, false)
    if err != nil {
        return []byte{}
    }
    // Not needed if we make the Decode return a FullFeaturedState
    // Might want to use phase0.InitState instead?
    // TODO requires more initialization - could try InitState, but need to catch the panic
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
