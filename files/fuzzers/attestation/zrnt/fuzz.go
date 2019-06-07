package fuzz

import (
	"github.com/protolambda/zrnt/eth2/beacon/block_processing"
    "helper"
)

func init() {
    helper.SetInputType(helper.INPUT_TYPE_ATTESTATION)
}

func Fuzz(data []byte) []byte {
    input, err := helper.DecodeAttestation(data, false)
    if err != nil {
        return []byte{}
    }

    helper.CorrectInvariants(input.Pre)

    if err := block_processing.ProcessAttestation(&input.Pre, &input.Attestation); err != nil {
        return []byte{}
    }

    return helper.EncodePoststate(input.Pre)
}
