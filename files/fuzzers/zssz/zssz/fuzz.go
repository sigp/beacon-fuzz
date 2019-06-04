package fuzz

import "C"

import (
	"github.com/protolambda/zrnt/eth2/beacon"
    "github.com/protolambda/zssz"
    . "github.com/protolambda/zssz/types"
    "reflect"
    "bytes"
    "bufio"
)

type Input struct {
	Pre         beacon.BeaconState
	Block       beacon.BeaconBlock
}

var ssz *SSZ

func Fuzz(data []byte) []byte {
    reader := bytes.NewReader(data)

    if ssz == nil {
        ssz_, err := SSZFactory(reflect.TypeOf(new(Input)).Elem())
        if err != nil {
            panic("Could not create object from factory")
        }
        ssz = &ssz_
    }

    dst := Input{}
    err := zssz.Decode(reader, uint32(len(data)), &dst, *ssz)
    if err == nil {
        var b bytes.Buffer
        writer := bufio.NewWriter(&b)
        err = zssz.Encode(writer, &dst, *ssz)
        if err != nil {
            panic("Cannot encode")
        }

        result := b.Bytes()
        if len(result) > len(data) {
            panic("Encoded slice is longer than input slice")
        }

        data := data[0:len(result)]
        if !bytes.Equal(result, data) {
            panic("Serialization asymmetry (input != Encode(Decode(input))")
        }
    }

    return []byte{}
}
