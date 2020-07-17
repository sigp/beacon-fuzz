package main

import (
	"context"
	"unsafe"
	"reflect"

	"github.com/prysmaticlabs/prysm/beacon-chain/core/blocks"
	stateTrie "github.com/prysmaticlabs/prysm/beacon-chain/state"
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

// process the given beaconstate and attestation pointer
// post beaconstate is store inside out_ptr
// return false if something failed

//export pfuzz_attestation
func pfuzz_attestation(
	beacon_ptr unsafe.Pointer, input_size int,
	attest_ptr unsafe.Pointer, attest_size int,
	out_ptr unsafe.Pointer, out_size int) (bool) {

	// mainnet config
	params.UseMainnetConfig()

	// Create reflect for the beaconstate pointer 
	var beacon []byte
	s1 := (*reflect.SliceHeader)(unsafe.Pointer(&beacon))
	s1.Data = uintptr(beacon_ptr)
	s1.Len = input_size
	s1.Cap = input_size


	// UnmarshalSSZ the beaconstate
	beaconstate := &pb.BeaconState{}
	if err := beaconstate.UnmarshalSSZ(beacon); err != nil {
		return false
	}

	// Create reflect for the Attestation pointer  
	var attest []byte
	s2 := (*reflect.SliceHeader)(unsafe.Pointer(&attest))
	s2.Data = uintptr(attest_ptr)
	s2.Len = attest_size
	s2.Cap = attest_size

	// UnmarshalSSZ the Attestation
	data := &ethpb.Attestation{}
	if err := data.UnmarshalSSZ(attest); err != nil {
		return false
	}

	// Initialize with the beaconstate
	s, err := stateTrie.InitializeFromProto(beaconstate)
	if err != nil {
		// should never happen
		return false
	}

	// process the container
	post, err := blocks.ProcessAttestationNoVerify(context.Background(), s, data)
	if err != nil {
		return false
	}

	// marshalSSZ the post beaconstate into ssz format
	post_ssz, err := ssz.Marshal(post.InnerStateUnsafe())
	if err != nil {
		panic(err)
	}

	// Create reflect for out_ptr
	var out []byte
	s3 := (*reflect.SliceHeader)(unsafe.Pointer(&out))
	s3.Data = uintptr(out_ptr)
	s3.Len = len(post_ssz)
	s3.Cap = len(post_ssz)

	// TODO - check len(result) == out_size?

	// copy post_ssz into out_ptr
	copy(out, post_ssz)

	return true
}

// before compilation
// go get .

// compilation to .a
// go build -o libpfuzz.a -buildmode=c-archive pfuzz.go
