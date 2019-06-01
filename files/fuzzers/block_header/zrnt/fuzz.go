package fuzz

import "C"

import (
	"github.com/protolambda/zrnt/eth2/beacon"
	"github.com/protolambda/zrnt/eth2/beacon/block_processing"
    go_ssz "github.com/prysmaticlabs/go-ssz"
    "bytes"
    "bufio"

	"github.com/protolambda/zrnt/eth2/util/ssz"
	"github.com/protolambda/zrnt/eth2/core"
)

type Input struct {
	Pre         beacon.BeaconState
	Block       beacon.BeaconBlock
}

func Fuzz(data []byte) []byte {
    reader := bytes.NewReader(data)

    var input Input;
    if err := go_ssz.Decode(reader, &input); err != nil {
        return []byte{}
    }

    if err := block_processing.ProcessBlockHeader(&input.Pre, &input.Block); err != nil {
        return []byte{}
    }

    var ret bytes.Buffer
    writer := bufio.NewWriter(&ret)
    if err := go_ssz.Encode(writer, input.Pre); err != nil {
        return []byte{}
    }

    return ret.Bytes()
}

var g_return_data = make([]byte, 0);

//export SSZPreprocessGetReturnData
func SSZPreprocessGetReturnData(return_data []byte) {
    copy(return_data, g_return_data)
}

//export SSZPreprocess
func SSZPreprocess(data []byte) int {
    g_return_data = []byte{}
    var input Input;

    /* Decode */
    {
        reader := bytes.NewReader(data)
        if err := go_ssz.Decode(reader, &input); err != nil {
            return 0
        }
    }

    /* Modify */

    /* Set PreviousBlockRoot to the expected value. It is too difficult
       for the fuzzer to brute-force this value.
    */
    {
        input.Block.PreviousBlockRoot = ssz.SigningRoot(input.Pre.LatestBlockHeader)
    }

    /* Avoid division by zero */
    {
        state := input.Pre
        epoch := state.Epoch()
        committeesPerSlot := state.GetEpochCommitteeCount(epoch) / uint64(core.SLOTS_PER_EPOCH)
        offset := core.Shard(committeesPerSlot) * core.Shard(state.Slot%core.SLOTS_PER_EPOCH)
        shard := (state.GetEpochStartShard(epoch) + offset) % core.SHARD_COUNT
        firstCommittee := input.Pre.GetCrosslinkCommittee(epoch, shard)
        if len(firstCommittee) == 0 {
            return 0
        }
    }

    var ret bytes.Buffer

    /* Encode */
    {
        writer := bufio.NewWriter(&ret)
        if err := go_ssz.Encode(writer, input); err != nil {
            g_return_data = []byte{}
            return len(g_return_data)
        }
    }

    /* Return modified, SSZ-encoded array */
    g_return_data = ret.Bytes()
    return len(g_return_data)
}
