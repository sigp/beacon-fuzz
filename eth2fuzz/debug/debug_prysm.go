package main
	
import (
    "fmt"
    "io/ioutil"
    "os"
    //"path/filepath"
    //"math/rand"
    //"time"
)

import (
	"context"

	ethpb "github.com/prysmaticlabs/ethereumapis/eth/v1alpha1"
	pb "github.com/prysmaticlabs/prysm/proto/beacon/p2p/v1"
	stateTrie "github.com/prysmaticlabs/prysm/beacon-chain/state"
	//"github.com/prysmaticlabs/go-ssz"
	"github.com/prysmaticlabs/prysm/beacon-chain/core/blocks"
	//"github.com/prysmaticlabs/prysm/shared/params/spectest"
	//"github.com/prysmaticlabs/prysm/shared/testutil"
	"github.com/prysmaticlabs/prysm/shared/params"
)

func check(e error) {
    if e != nil {
        fmt.Println("Error:", e)
        //panic(e)
    }
}


func main() {

	params.UseMainnetConfig()

	// get beaconstate
	beaconstate := os.Args[1]
    data, err := ioutil.ReadFile(beaconstate)
    check(err)
    fmt.Println("ReadFile OK: ", beaconstate)
    beacon := &pb.BeaconState{}
	if err := beacon.UnmarshalSSZ(data); err != nil {
		fmt.Println("Failed to unmarshal: %v", err)
		panic(" BeaconState")
	}
    fmt.Println("one beaconstate valid found:")


	// handle ProposerSlashing
	container := os.Args[2]
    d, err := ioutil.ReadFile(container)
    check(err)
    fmt.Println("ReadFile OK: ", container)
	//var att ethpb.ProposerSlashing
	att := &ethpb.ProposerSlashing{}
	if err := att.UnmarshalSSZ(d); err != nil {
		fmt.Println("Failed to unmarshal: %v", err)
		panic(" Unmarshal")
	}

	// initialize state
    s, err := stateTrie.InitializeFromProto(beacon)
	if err != nil {
		panic("stateTrie InitializeFromProto")
	}

	post, err := blocks.ProcessProposerSlashings(context.Background(), s, &ethpb.BeaconBlockBody{ProposerSlashings: []*ethpb.ProposerSlashing{att}})
	if err != nil {
		fmt.Println("ProcessProposerSlashings failed")
	}

	if post == nil {
		fmt.Println("post nil")
	}

	fmt.Println("OK")
}

// compilation
// go build debug_prysm_attestation.go

// ./debug_prysm_attestation beaconstate.ssz ProposerSlashing.ssz
