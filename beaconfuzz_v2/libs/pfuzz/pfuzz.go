package main

import "C"
import (
	"context"
	"unsafe"
	"reflect"

	"github.com/prysmaticlabs/prysm/beacon-chain/core/blocks"
	stateTrie "github.com/prysmaticlabs/prysm/beacon-chain/state"
	// prylabs_testing "github.com/prysmaticlabs/prysm/fuzz/testing"
	"github.com/prysmaticlabs/prysm/shared/params"
	"github.com/prysmaticlabs/prysm/shared/featureconfig"
	ethpb "github.com/prysmaticlabs/ethereumapis/eth/v1alpha1"
	pb "github.com/prysmaticlabs/prysm/proto/beacon/p2p/v1"
	ssz "github.com/prysmaticlabs/go-ssz"
)

func main() {}

//export PrysmMain
func PrysmMain(bls bool) {
	featureconfig.Init(&featureconfig.Flags{
		SkipBLSVerify: bls,
	})
}

func fail(err error) (bool) {
	shouldPanic := false
	if shouldPanic {
		panic(err)
	}
	return false
}

/*

        input_ptr: *mut u8,
        input_size: usize,
        output_ptr: *mut u8,
        output_size: *mut usize,
        disable_bls: bool,

(uint8_t* input_ptr, size_t input_size,
  uint8_t* output_ptr, size_t* output_size, bool disable_bls);
*/

// BeaconFuzzAttestation implements libfuzzer and beacon fuzz interface.
//export pfuzz_attestation
func pfuzz_attestation(
	beacon_ptr unsafe.Pointer, input_size int,
	attest_ptr unsafe.Pointer, attest_size int,
	out_ptr unsafe.Pointer, out_size int) (bool) {
	// mainnet config
	params.UseMainnetConfig()

	// pointer into beaconstate 
	var beacon []byte
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&beacon))
	sh.Data = uintptr(beacon_ptr)
	sh.Len = input_size
	sh.Cap = input_size


	// load the beaconstate
	st := &pb.BeaconState{}
	if err := st.UnmarshalSSZ(beacon); err != nil {
		//return false
		panic("BeaconState failed ")
		return false
	}

	// pointer into Attestation 
	var attest []byte
	sa := (*reflect.SliceHeader)(unsafe.Pointer(&attest))
	sa.Data = uintptr(attest_ptr)
	sa.Len = attest_size
	sa.Cap = attest_size

	// load the beaconstate
	data := &ethpb.Attestation{}
	if err := data.UnmarshalSSZ(attest); err != nil {
		panic("Attestation failed ")
		return false
	}

	// get a valid beaconstate
	//st := getbeaconstate()
	s, err := stateTrie.InitializeFromProto(st)
	if err != nil {
		// should never happen
		panic("stateTrie InitializeFromProto")
	}
	// process the container
	post, err := blocks.ProcessAttestationNoVerify(context.Background(), s, data)
	if err != nil {
		return false
	}
	if post == nil {
		return false
	}

	result, err := ssz.Marshal(post.InnerStateUnsafe())
	if err != nil {
		panic(err)
	}

	// pointer into Attestation 
	var out []byte
	so := (*reflect.SliceHeader)(unsafe.Pointer(&out))
	so.Data = uintptr(out_ptr)
	so.Len = len(result)
	so.Cap = len(result)

	// TODO - check len(result) == out_size?

	copy(out, result)

	return true
}

// before compilation
// go get .

// compilation to .a
// go build -o libpfuzz.a -buildmode=c-archive pfuzz.go
