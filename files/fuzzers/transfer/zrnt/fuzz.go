package fuzz

import "C"

import (
	"github.com/protolambda/zrnt/eth2/beacon"
	"github.com/protolambda/zrnt/eth2/beacon/block_processing"
    go_ssz "github.com/prysmaticlabs/go-ssz"
    "bytes"
    "bufio"
)

type Input struct {
	Pre         beacon.BeaconState
	Transfer    beacon.Transfer
}

func Fuzz(data []byte) []byte {
    reader := bytes.NewReader(data)

    var input Input;
    if err := go_ssz.Decode(reader, &input); err != nil {
        return []byte{}
    }

    if err := block_processing.ProcessTransfer(&input.Pre, &input.Transfer); err != nil {
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

    /* Invariant */
    {
        if len(input.Pre.Balances) != len(input.Pre.ValidatorRegistry) {
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
