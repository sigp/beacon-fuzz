package fuzz

import (
	"github.com/protolambda/zrnt/eth2/beacon"
	"github.com/protolambda/zrnt/eth2/beacon/block_processing"
    go_ssz "github.com/prysmaticlabs/go-ssz"
    "bytes"
    "bufio"
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
