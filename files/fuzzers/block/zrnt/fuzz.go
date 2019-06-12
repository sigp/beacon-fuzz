package fuzz

import (
    "helper"
    "github.com/protolambda/zrnt/eth2/beacon/transition"
)

func init() {
    helper.SetInputType(helper.INPUT_TYPE_STATE_BLOCK)
}

func Fuzz(data []byte) []byte {
    stateBlock, err := helper.DecodeStateBlock(data, false)
    if err != nil {
        return []byte{}
    }

    err = transition.StateTransition(&stateBlock.State, &stateBlock.Block, false)

    if err != nil {
        return []byte{}
    }

    return helper.EncodeState(stateBlock.State)
}
