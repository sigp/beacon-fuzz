package fuzz

import (
    "helper"
    "github.com/protolambda/zrnt/eth2/beacon"
    "github.com/protolambda/zrnt/eth2/core"
    "github.com/protolambda/zrnt/eth2/beacon/transition"
	zrnt_ssz "github.com/protolambda/zrnt/eth2/util/ssz"
    "encoding/binary"
)

func init() {
    helper.SetInputType(helper.INPUT_TYPE_BLOCK_WRAPPER)
}

func RandomlyValid(valid []byte, random []byte, chance float32) {
	chanceRNG := binary.LittleEndian.Uint32(random[:4])
	bit := random[4]
	// make random all valid
	copy(random, valid)
	v := float32(float64(chanceRNG) / float64(^uint32(0)))
	// now mutate random bit based on chance
	if v > chance || chance == 0 {
		random[bit >> 3] ^= 1 << (bit & 0x7)
	}
}

func Fuzz(data []byte) []byte {
    blockWrapper, err := helper.DecodeBlockWrapper(data, false)
    if err != nil {
        return []byte{}
    }

    state, err := helper.GetStateByID(blockWrapper.StateID)

    if err != nil {
        return []byte{}
    }

    /* Start block corrections */
    {
        blockWrapper.Block.Slot = state.Slot + (blockWrapper.Block.Slot % 10)
    }

    {
        latestHeaderCopy := state.LatestBlockHeader
        latestHeaderCopy.StateRoot = zrnt_ssz.HashTreeRoot(state, beacon.BeaconStateSSZ)
        prevRoot := zrnt_ssz.SigningRoot(latestHeaderCopy, beacon.BeaconBlockHeaderSSZ)
        RandomlyValid(prevRoot[:], blockWrapper.Block.PreviousBlockRoot[:], 0.9)
    }

    {
        for i := 0; i < len(blockWrapper.Block.Body.Attestations); i++ {
            data := &blockWrapper.Block.Body.Attestations[i].Data
            if data.Shard < core.Shard(len(state.CurrentCrosslinks)) {
                data.PreviousCrosslinkRoot = zrnt_ssz.HashTreeRoot(state.CurrentCrosslinks[data.Shard], beacon.CrosslinkSSZ)
            }
        }
    }
    /* End block corrections */

    err = transition.StateTransition(&state, &blockWrapper.Block, false)

    if err != nil {
        return []byte{}
    }

    return helper.Encode(&state)
}
