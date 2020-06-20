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

	ethpb "github.com/prysmaticlabs/ethereumapis/eth/v1alpha1"
	pb "github.com/prysmaticlabs/prysm/proto/beacon/p2p/v1"
	stateTrie "github.com/prysmaticlabs/prysm/beacon-chain/state"
	"github.com/prysmaticlabs/prysm/beacon-chain/core/state"
	//"github.com/prysmaticlabs/go-ssz"
	"github.com/prysmaticlabs/prysm/beacon-chain/core/blocks"
	//"github.com/prysmaticlabs/prysm/shared/params/spectest"
	//"github.com/prysmaticlabs/prysm/shared/testutil"
	"github.com/prysmaticlabs/prysm/shared/params"
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
			fmt.Println("beaconstate choosen: ", file_name)
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
	post, err := blocks.ProcessAttestationNoVerify(context.Background(), s, data)
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
	post, err := blocks.ProcessAttesterSlashings(context.Background(), s, &ethpb.BeaconBlockBody{AttesterSlashings: []*ethpb.AttesterSlashing{data}})
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
	post, err := blocks.ProcessDeposit(s, data)
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
	// process the container
	post, err := blocks.ProcessProposerSlashings(context.Background(), s, &ethpb.BeaconBlockBody{ProposerSlashings: []*ethpb.ProposerSlashing{data}})
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
	data := &ethpb.VoluntaryExit{}
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
	post, err := blocks.ProcessVoluntaryExitsNoVerify(s, &ethpb.BeaconBlockBody{VoluntaryExits: []*ethpb.SignedVoluntaryExit{{Exit: data}}})
	if err != nil {
		return 0
	}
	if post == nil {
		return 0
	}
	return 1
}