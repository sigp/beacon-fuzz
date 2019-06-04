package fuzz

import (
	"github.com/protolambda/zrnt/eth2/beacon"
	"github.com/protolambda/zrnt/eth2/beacon/block_processing"
    "helper"
)

type Input struct {
	Pre         beacon.BeaconState
	Attestation beacon.Attestation
}

func Fuzz(data []byte) []byte {
    var input Input
    if err := helper.Decode(data, &input); err != nil {
        return []byte{}
    }

    helper.CorrectInvariants(input.Pre)

    if err := block_processing.ProcessAttestation(&input.Pre, &input.Attestation); err != nil {
        return []byte{}
    }

    return helper.EncodePoststate(input.Pre)
}
