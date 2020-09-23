// +build gofuzz

package prysm

import (
    "fmt"
    "io/ioutil"
    "os"
    "path/filepath"
    "math/rand"
    "time"
)

import (
	"context"
	"bytes"

	ethpb "github.com/prysmaticlabs/ethereumapis/eth/v1alpha1"
	pb "github.com/prysmaticlabs/prysm/proto/beacon/p2p/v1"
	stateTrie "github.com/prysmaticlabs/prysm/beacon-chain/state"
	"github.com/prysmaticlabs/prysm/beacon-chain/core/state"
	//"github.com/prysmaticlabs/go-ssz"
	"github.com/prysmaticlabs/prysm/beacon-chain/core/blocks"
	//"github.com/prysmaticlabs/prysm/shared/params/spectest"
	//"github.com/prysmaticlabs/prysm/shared/testutil"
	"github.com/prysmaticlabs/prysm/shared/params"

	"github.com/prysmaticlabs/prysm/beacon-chain/p2p/encoder"
	testpb "github.com/prysmaticlabs/prysm/proto/testing"
	rpc "github.com/prysmaticlabs/prysm/proto/beacon/rpc/v1"
	db "github.com/prysmaticlabs/prysm/proto/beacon/db"

)


func Shuffle(vals []string) {
  r := rand.New(rand.NewSource(time.Now().Unix()))
  for len(vals) > 0 {
    n := len(vals)
    randIndex := r.Intn(n)
    vals[n-1], vals[randIndex] = vals[randIndex], vals[n-1]
    vals = vals[:n-1]
  }
}

const fileBase = "not_existing" // TODO simplify
const fileBaseENV = "ETH2FUZZ_BEACONSTATE"

var GlobalBeaconstate = getbeaconstate()

// TODO - optimize to only be called once by libfuzzer
func getbeaconstate() (*pb.BeaconState){

	base := fileBase
	var files []string

	// get environment variable
	if p, ok := os.LookupEnv(fileBaseENV); ok {
		base = p  // should always be executed
				// otherwise ETH2FUZZ_BEACONSTATE is not set
	}
	// print the env variable
	// fmt.Println("ETH2FUZZ_BEACONSTATE:", base)

	// get all files paths
    err := filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
        files = append(files, path)
        return nil
    })
    if err != nil {
        panic("empty ETH2FUZZ_BEACONSTATE")
    }

    // shuffle the beaconstates files names
    Shuffle(files)

	st := &pb.BeaconState{}
    // iterate over all beaconstate
    for _, file_name := range files {
	    data, err := ioutil.ReadFile(file_name)
	    if err != nil {
	        continue
	    }

	    st := &pb.BeaconState{}
		if err := st.UnmarshalSSZ(data); err == nil {
			// we found a good beaconstate
			// TODO - add beaconstate filename to a logging file
			fmt.Println("beaconstate chosen: ", file_name)
			break
		}
    }
    return st
}

func Prysm_attestation(b []byte) int {
	params.UseMainnetConfig()
	data := &ethpb.Attestation{}
	if err := data.UnmarshalSSZ(b); err != nil {
		return 0
	}
	// get a valid beaconstate
	//st := getbeaconstate()
	s, err := stateTrie.InitializeFromProto(GlobalBeaconstate)
	if err != nil {
		// should never happen
		panic("stateTrie InitializeFromProto")
	}
	// process the container
	post, err := blocks.ProcessAttestationNoVerifySignature(context.Background(), s, data)
	if err != nil {
		return 0
	}
	if post == nil {
		return 0
	}
	return 1
}

func Prysm_attester_slashing(b []byte) int {
	params.UseMainnetConfig()
	data := &ethpb.AttesterSlashing{}
	if err := data.UnmarshalSSZ(b); err != nil {
		return 0
	}
	// get a valid beaconstate
	//st := getbeaconstate()
	s, err := stateTrie.InitializeFromProto(GlobalBeaconstate)
	if err != nil {
		// should never happen
		panic("stateTrie InitializeFromProto")
	}
	// process the container
	block := &ethpb.SignedBeaconBlock{
		Block: &ethpb.BeaconBlock{
			Body: &ethpb.BeaconBlockBody{AttesterSlashings: []*ethpb.AttesterSlashing{data}},
		},
	}
	post, err := blocks.ProcessAttesterSlashings(context.Background(), s, block)
	if err != nil {
		return 0
	}
	if post == nil {
		return 0
	}
	return 1
}

func Prysm_block(b []byte) int {
	params.UseMainnetConfig()
	data := &ethpb.SignedBeaconBlock{}
	if err := data.UnmarshalSSZ(b); err != nil {
		return 0
	}
	// get a valid beaconstate
	//st := getbeaconstate()
	s, err := stateTrie.InitializeFromProto(GlobalBeaconstate)
	if err != nil {
		// should never happen
		panic("stateTrie InitializeFromProto")
	}
	// process the container
	post, err := state.ProcessBlock(context.Background(), s, data)
	if err != nil {
		return 0
	}
	if post == nil {
		return 0
	}
	return 1
}

func Prysm_block_header(b []byte) int {
	params.UseMainnetConfig()
	data := &ethpb.BeaconBlock{}
	if err := data.UnmarshalSSZ(b); err != nil {
		return 0
	}
	// get a valid beaconstate
	//st := getbeaconstate()
	s, err := stateTrie.InitializeFromProto(GlobalBeaconstate)
	if err != nil {
		// should never happen
		panic("stateTrie InitializeFromProto")
	}
	// process the container
	post, err := blocks.ProcessBlockHeaderNoVerify(s, data)
	if err != nil {
		return 0
	}
	if post == nil {
		return 0
	}
	return 1
}

func Prysm_deposit(b []byte) int {
	params.UseMainnetConfig()
	data := &ethpb.Deposit{}
	if err := data.UnmarshalSSZ(b); err != nil {
		return 0
	}
	// get a valid beaconstate
	//st := getbeaconstate()
	s, err := stateTrie.InitializeFromProto(GlobalBeaconstate)
	if err != nil {
		// should never happen
		panic("stateTrie InitializeFromProto")
	}
	// process the container
	post, err := blocks.ProcessDeposit(s, data, true)
	if err != nil {
		return 0
	}
	if post == nil {
		return 0
	}
	return 1
}

func Prysm_proposer_slashing(b []byte) int {
	params.UseMainnetConfig()
	data := &ethpb.ProposerSlashing{}
	if err := data.UnmarshalSSZ(b); err != nil {
		return 0
	}
	// get a valid beaconstate
	//st := getbeaconstate()
	s, err := stateTrie.InitializeFromProto(GlobalBeaconstate)
	if err != nil {
		// should never happen
		panic("stateTrie InitializeFromProto")
	}
	block := &ethpb.SignedBeaconBlock{
		Block: &ethpb.BeaconBlock{
			Body: &ethpb.BeaconBlockBody{ProposerSlashings: []*ethpb.ProposerSlashing{data}},
		},
	}
	// process the container
	post, err := blocks.ProcessProposerSlashings(context.Background(), s, block)
	if err != nil {
		return 0
	}
	if post == nil {
		return 0
	}
	return 1
}

func Prysm_voluntary_exit(b []byte) int {
	params.UseMainnetConfig()
	data := &ethpb.SignedVoluntaryExit{}
	if err := data.UnmarshalSSZ(b); err != nil {
		return 0
	}
	// get a valid beaconstate
	//st := getbeaconstate()
	s, err := stateTrie.InitializeFromProto(GlobalBeaconstate)
	if err != nil {
		// should never happen
		panic("stateTrie InitializeFromProto")
	}
	// process the container
	post, err := blocks.ProcessVoluntaryExitsNoVerifySignature(s, &ethpb.BeaconBlockBody{VoluntaryExits: []*ethpb.SignedVoluntaryExit{data}})
	if err != nil {
		return 0
	}
	if post == nil {
		return 0
	}
	return 1
}


// following are some testing fuzzing harnesses
// they are not supposed to be callable from eth2fuzz



//
// P2P
// https://github.com/prysmaticlabs/prysm/tree/master/proto/beacon/p2p/v1
//

// SszEncoderAttestationFuzz runs network decode for attestations.
func SszDecodeAttestationFuzz(b []byte) int {
	params.UseMainnetConfig()
	input := &ethpb.Attestation{}
	e := encoder.SszNetworkEncoder{}
	if err := e.DecodeGossip(b, input); err != nil {
		_ = err
		return 0
	}
	return 1
}


// runs network decode for TestSimpleMessage.
func DecodeTestSimpleMessage(b []byte) int {
	params.UseMainnetConfig()
	input := &testpb.TestSimpleMessage{}
	e := encoder.SszNetworkEncoder{}
	if err := e.DecodeGossip(b, input); err != nil {
		_ = err
		return 0
	}
	return 1
}


// runs network decode for CheckPtInfo.
func DecodeCheckPtInfo(b []byte) int {
	params.UseMainnetConfig()
	input := &pb.CheckPtInfo{}
	e := encoder.SszNetworkEncoder{}
	if err := e.DecodeGossip(b, input); err != nil {
		_ = err
		return 0
	}
	return 1
}

// runs network decode for PendingAttestation.
func DecodePendingAttestation(b []byte) int {
	params.UseMainnetConfig()
	input := &pb.PendingAttestation{}
	e := encoder.SszNetworkEncoder{}
	if err := e.DecodeGossip(b, input); err != nil {
		_ = err
		return 0
	}
	return 1
}

// runs network decode for ENRForkID.
func DecodeENRForkID(b []byte) int {
	data := bytes.NewReader(b)
	params.UseMainnetConfig()
	input := &pb.ENRForkID{}
	e := encoder.SszNetworkEncoder{}
	if err := e.DecodeWithMaxLength(data, input); err != nil {
		_ = err
		return 0
	}
	return 1
}
// runs network decode for MetaData.
func DecodeMetaData(b []byte) int {
	params.UseMainnetConfig()
	input := &pb.MetaData{}
	e := encoder.SszNetworkEncoder{}
	if err := e.DecodeGossip(b, input); err != nil {
		_ = err
		return 0
	}
	return 1
}
// runs network decode for Fork.
func DecodeFork(b []byte) int {
	params.UseMainnetConfig()
	input := &pb.Fork{}
	e := encoder.SszNetworkEncoder{}
	if err := e.DecodeGossip(b, input); err != nil {
		_ = err
		return 0
	}
	return 1
}

// runs network decode for ForkData.
func DecodeForkData(b []byte) int {
	params.UseMainnetConfig()
	input := &pb.ForkData{}
	e := encoder.SszNetworkEncoder{}
	if err := e.DecodeGossip(b, input); err != nil {
		_ = err
		return 0
	}
	return 1
}

// runs network decode for HistoricalBatch.
func DecodeHistoricalBatch(b []byte) int {
	params.UseMainnetConfig()
	input := &pb.HistoricalBatch{}
	e := encoder.SszNetworkEncoder{}
	if err := e.DecodeGossip(b, input); err != nil {
		_ = err
		return 0
	}
	return 1
}


// runs network decode for Status.
func DecodeStatus(b []byte) int {
	params.UseMainnetConfig()
	input := &pb.Status{}
	e := encoder.SszNetworkEncoder{}
	if err := e.DecodeGossip(b, input); err != nil {
		_ = err
		return 0
	}
	return 1
}


func SszDecodeBeaconState(b []byte) int {
	params.UseMainnetConfig()
	input := &pb.BeaconState{}
	e := encoder.SszNetworkEncoder{}
	if err := e.DecodeGossip(b, input); err != nil {
		_ = err
		return 0
	}
	return 1
}


// runs network decode for SigningData.
func DecodeSigningData(b []byte) int {
	params.UseMainnetConfig()
	input := &pb.SigningData{}
	e := encoder.SszNetworkEncoder{}
	if err := e.DecodeGossip(b, input); err != nil {
		_ = err
		return 0
	}
	return 1
}

//
// RPC
// https://github.com/prysmaticlabs/prysm/tree/master/proto/beacon/rpc/v1
//

// runs network decode for ProtoArrayForkChoiceResponse.
func DecodeProtoArrayForkChoiceResponse(b []byte) int {
	params.UseMainnetConfig()
	input := &rpc.ProtoArrayForkChoiceResponse{}
	e := encoder.SszNetworkEncoder{}
	if err := e.DecodeGossip(b, input); err != nil {
		_ = err
		return 0
	}
	return 1
}

//
// DB
// https://github.com/prysmaticlabs/prysm/tree/master/proto/beacon/db
//

// runs decode for ETH1ChainData.
func DecodeETH1ChainData(b []byte) int {
	params.UseMainnetConfig()
	input := &db.ETH1ChainData{}
	e := encoder.SszNetworkEncoder{}
	if err := e.DecodeGossip(b, input); err != nil {
		_ = err
		return 0
	}
	return 1
}

