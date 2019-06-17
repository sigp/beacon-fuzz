package fuzz

import (
    "helper"
    "github.com/protolambda/zrnt/eth2/beacon/transition"
    "github.com/cespare/xxhash"
    //"github.com/protolambda/zrnt/eth2/util/hashing"
    //"github.com/protolambda/zrnt/eth2/util/ssz"
)

func xxhash256(input []byte) [32]byte {
    var ret [32]byte
    hash := xxhash.Sum64(input)
    ret[0] = byte(hash & 0xFF)
    ret[1] = byte(hash >> 8) & 0xFF
    ret[2] = byte(hash >> 16) & 0xFF
    ret[3] = byte(hash >> 24) & 0xFF
    ret[4] = byte(hash >> 32) & 0xFF
    ret[5] = byte(hash >> 40) & 0xFF
    ret[6] = byte(hash >> 48) & 0xFF
    ret[7] = byte(hash >> 56) & 0xFF
    return ret
}

func init() {
    helper.SetInputType(helper.INPUT_TYPE_BLOCK_WRAPPER)

    /* Uncomment once PySpec can use xxhash */
    /*
    ssz.InitZeroHashes(xxhash256)
    hashing.Hash = xxhash256
    hashing.GetHashFn = func() hashing.HashFn {
        return xxhash256
    }
    */
}

func Fuzz(data []byte) []byte {
    blockWrapper, err := helper.DecodeBlockWrapper(data, false)
    if err != nil {
        panic("Decoding failed")
    }
    state, err := helper.GetStateByID(blockWrapper.StateID)
    if err != nil {
        panic("Retrieving state failed")
    }

    err = transition.StateTransition(&state, &blockWrapper.Block, false)

    if err != nil {
        return []byte{}
    }

    return helper.EncodeState(state)
}
