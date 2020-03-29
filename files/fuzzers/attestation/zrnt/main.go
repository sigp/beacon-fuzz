// +build ignore

package main

import (
	"unsafe"
)

// #include <stdint.h>
import "C"

//export attestation_LLVMFuzzerInitialize
func attestation_LLVMFuzzerInitialize(argc uintptr, argv uintptr) int {
	// Do nothing
	return 0
}

var g_return_data = make([]byte, 0)

//export attestation_get_return_size
func attestation_get_return_size() int {
	return len(g_return_data)
}

//export attestation_get_return_data
func attestation_get_return_data(return_data []byte) {
	// Note: we prob want this to crash if the copy results in a re-allocation
	copy(return_data, g_return_data)
}

//export attestation_LLVMFuzzerTestOneInput
func attestation_LLVMFuzzerTestOneInput(data *C.char, size C.size_t) C.int {
	// TODO(mdempsky): Use unsafe.Slice once golang.org/issue/19367 is accepted.
	// TODO(gnattishness) understand this cast notation
	input := (*[1 << 30]byte)(unsafe.Pointer(data))[:size:size]
	g_return_data = Fuzz(input)
	return 0
}

func main() {
}
