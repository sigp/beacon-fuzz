package helper

import "C"

import (
	"github.com/protolambda/zrnt/eth2/core"
	"github.com/protolambda/zrnt/eth2/beacon"
    "github.com/protolambda/zssz"
    "github.com/protolambda/zssz/types"
    "bytes"
    "reflect"
    "errors"
    "bufio"
)

type InputType uint64

const INPUT_TYPE_INVALID InputType = 0
const INPUT_TYPE_ATTESTATION InputType = 1
const INPUT_TYPE_ATTESTER_SLASHING InputType = 2
const INPUT_TYPE_BLOCK_HEADER InputType = 3
const INPUT_TYPE_DEPOSIT InputType = 4
const INPUT_TYPE_TRANSFER InputType = 5
const INPUT_TYPE_VOLUNTARY_EXIT InputType = 6

var inputType InputType = INPUT_TYPE_INVALID

type InputAttestation struct {
	Pre         beacon.BeaconState
	Attestation beacon.Attestation
}

type InputAttesterSlashing struct {
	Pre                 beacon.BeaconState
	AttesterSlashing    beacon.AttesterSlashing
}

type InputBlockHeader struct {
	Pre         beacon.BeaconState
	Block       beacon.BeaconBlock
}

type InputDeposit struct {
	Pre         beacon.BeaconState
	Deposit     beacon.Deposit
}

type InputTransfer struct {
	Pre         beacon.BeaconState
	Transfer    beacon.Transfer
}

type InputVoluntaryExit struct {
	Pre             beacon.BeaconState
	VoluntaryExit   beacon.VoluntaryExit
}

var ssztype *types.SSZ
var statessztype *types.SSZ

func init() {
    statessztype_, err := types.SSZFactory(reflect.TypeOf(new(beacon.BeaconState)).Elem())
    if err != nil {
        panic("Could not create object from factory")
    }
    statessztype = &statessztype_
}

func SetInputType(inputType_ InputType) {
    inputType = inputType_
}

func getSSZType(dest interface{}) *types.SSZ {
    if ssztype == nil {
        ssztype_, err := types.SSZFactory(reflect.TypeOf(dest).Elem())
        if err != nil {
            panic("Could not create object from factory")
        }
        ssztype = &ssztype_
    }

    return ssztype
}

func CheckInvariants(state beacon.BeaconState, correct bool) error {
    /* Balances and ValidatorRegistry must be the same length */
    if len(state.Balances) != len(state.ValidatorRegistry) {
        if correct == false {
            return errors.New("Balances/ValidatorRegistry length mismatch")
        }
        if len(state.Balances) < len(state.ValidatorRegistry) {
            for i := 0; i < len(state.ValidatorRegistry); i++ {
                state.Balances = append(state.Balances, 0)
            }
        } else {
            for i := 0; i < len(state.Balances); i++ {
                var tmp beacon.Validator
                state.ValidatorRegistry = append(state.ValidatorRegistry, &tmp)
            }
        }
    }

    /* Avoid division by zero in ProcessBlockHeader */
    {
        epoch := state.Epoch()
        committeesPerSlot := state.GetEpochCommitteeCount(epoch) / uint64(core.SLOTS_PER_EPOCH)
        offset := core.Shard(committeesPerSlot) * core.Shard(state.Slot%core.SLOTS_PER_EPOCH)
        shard := (state.GetEpochStartShard(epoch) + offset) % core.SHARD_COUNT
        firstCommittee := state.GetCrosslinkCommittee(epoch, shard)
        if len(firstCommittee) == 0 {
            if correct == false {
                return errors.New("Empty firstCommittee")
            } else {
                /* TODO correct */
            }
        }
    }

    return nil
}

func CorrectInvariants(state beacon.BeaconState) {
    if err := CheckInvariants(state, true); err != nil {
        panic("CheckInvariants failed")
    }
}

func AssertInvariants(state beacon.BeaconState) {
    if err := CheckInvariants(state, false); err != nil {
        panic("Invariant check failed")
    }
}

func Decode(data []byte, dest interface{}) error {
    reader := bytes.NewReader(data)
    //if err := zssz.Decode(reader, uint32(len(data)), dest, *getSSZType(dest)); err != nil {
    if err, _ := zssz.DecodeFuzzBytes(reader, uint32(len(data)), dest, *getSSZType(dest)); err != nil {
        return errors.New("Cannot decode")
    }

    return nil
}

func DecodeAttestation(data []byte) (InputAttestation, error) {
    var input InputAttestation
    err := Decode(data, &input);
    return input, err
}

func DecodeAttesterSlashing(data []byte) (InputAttesterSlashing, error) {
    var input InputAttesterSlashing
    err := Decode(data, &input);
    return input, err
}

func DecodeBlockHeader(data []byte) (InputBlockHeader, error) {
    var input InputBlockHeader
    err := Decode(data, &input);
    return input, err
}

func DecodeDeposit(data []byte) (InputDeposit, error) {
    var input InputDeposit
    err := Decode(data, &input);
    return input, err
}

func DecodeTransfer(data []byte) (InputTransfer, error) {
    var input InputTransfer
    err := Decode(data, &input);
    return input, err
}

func DecodeVoluntaryExit(data []byte) (InputVoluntaryExit, error) {
    var input InputVoluntaryExit
    err := Decode(data, &input);
    return input, err
}

func Encode(src interface{}) []byte {
    var ret bytes.Buffer
    writer := bufio.NewWriter(&ret)
    if err := zssz.Encode(writer, src, *getSSZType(src)); err != nil {
        panic("Cannot encode")
    }

    return ret.Bytes()
}

func EncodeState(state beacon.BeaconState) []byte {
    var ret bytes.Buffer
    writer := bufio.NewWriter(&ret)
    if err := zssz.Encode(writer, &state, *statessztype); err != nil {
        panic("Cannot encode state")
    }

    return ret.Bytes()
}

func EncodePoststate(state beacon.BeaconState) []byte {
    AssertInvariants(state)

    return EncodeState(state)
}

func sszPreprocess(state beacon.BeaconState, err error) int {
    if err != nil {
        return 0
    }

    CorrectInvariants(state)
    g_return_data = EncodeState(state)
    return len(g_return_data)
}

var g_return_data = make([]byte, 0);

//export SSZPreprocessGetReturnData
func SSZPreprocessGetReturnData(return_data []byte) {
    copy(return_data, g_return_data)
}

//export SSZPreprocess
func SSZPreprocess(data []byte) int {
    switch inputType {
    case    INPUT_TYPE_ATTESTATION:
        input, err := DecodeAttestation(data)
        return sszPreprocess(input.Pre, err)
    case    INPUT_TYPE_BLOCK_HEADER:
        input, err := DecodeBlockHeader(data)
        return sszPreprocess(input.Pre, err)
    case    INPUT_TYPE_TRANSFER:
        input, err := DecodeTransfer(data)
        return sszPreprocess(input.Pre, err)
    case    INPUT_TYPE_VOLUNTARY_EXIT:
        input, err := DecodeVoluntaryExit(data)
        return sszPreprocess(input.Pre, err)
    default:
        panic("Invalid type configured")
    }
}

