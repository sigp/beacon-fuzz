package helper

import "C"

import (
	"github.com/protolambda/zrnt/eth2/core"
	zrnt_ssz "github.com/protolambda/zrnt/eth2/util/ssz"
	"github.com/protolambda/zrnt/eth2/beacon/attestations"
	"github.com/protolambda/zrnt/eth2/beacon/slashings/attslash"
	"github.com/protolambda/zrnt/eth2/beacon/slashings/propslash"
	"github.com/protolambda/zrnt/eth2/beacon/validator"
	"github.com/protolambda/zrnt/eth2/beacon/crosslinks"
	"github.com/protolambda/zrnt/eth2/beacon/header"
	"github.com/protolambda/zrnt/eth2/beacon/deposits"
	"github.com/protolambda/zrnt/eth2/beacon/transfers"
	"github.com/protolambda/zrnt/eth2/beacon/exits"
        "github.com/protolambda/zrnt/eth2/phase0"
    "github.com/protolambda/zssz"
    "github.com/protolambda/zssz/types"
    "bytes"
    "reflect"
    "errors"
    "bufio"
    "fmt"
    "io/ioutil"
    "os"
    "path"
    "encoding/binary"
)


type InputType uint64

const INPUT_TYPE_INVALID InputType = 0
const INPUT_TYPE_ATTESTATION InputType = 1
const INPUT_TYPE_ATTESTER_SLASHING InputType = 2
const INPUT_TYPE_BLOCK_HEADER InputType = 3
const INPUT_TYPE_DEPOSIT InputType = 4
const INPUT_TYPE_TRANSFER InputType = 5
const INPUT_TYPE_VOLUNTARY_EXIT InputType = 6
const INPUT_TYPE_PROPOSER_SLASHING InputType = 7
const INPUT_TYPE_BLOCK_WRAPPER InputType = 8

var inputType InputType = INPUT_TYPE_INVALID

type InputAttestation struct {
	Pre         phase0.BeaconState
	Attestation attestations.Attestation
}

type InputAttesterSlashing struct {
	Pre                 phase0.BeaconState
	AttesterSlashing    attslash.AttesterSlashing
}

type InputBlockHeader struct {
	Pre         phase0.BeaconState
	Block       phase0.BeaconBlock
}

type InputDeposit struct {
	Pre         phase0.BeaconState
	Deposit     deposits.Deposit
}

type InputTransfer struct {
	Pre         phase0.BeaconState
	Transfer    transfers.Transfer
}

type InputVoluntaryExit struct {
	Pre             phase0.BeaconState
	VoluntaryExit   exits.VoluntaryExit
}

type InputProposerSlashing struct {
	Pre                 phase0.BeaconState
	ProposerSlashing    propslash.ProposerSlashing
}

type InputBlockWrapper struct {
	StateID             uint32
	Block               phase0.BeaconBlock
}

type InputStateBlock   struct {
	State               phase0.BeaconState
	Block               phase0.BeaconBlock
}

// TODO should this be a []phase0.FullFeaturedState instead?
var PreloadedStates = make([]phase0.BeaconState, 0);

var ssztype *types.SSZ
var blockWrapperSSZType types.SSZ
var stateBlockSSZType types.SSZ

func loadPrestates() {
    stateCorpusPath := os.Getenv("ETH2_FUZZER_STATE_CORPUS_PATH")
    if len(stateCorpusPath) == 0 {
        panic("Environment variable \"ETH2_FUZZER_STATE_CORPUS_PATH\" not set or empty")
    }

    stateID := 0
    for {

        var state phase0.BeaconState

        filename := path.Join(stateCorpusPath, fmt.Sprintf("%v", stateID))

        data, err := ioutil.ReadFile(filename)
        if err != nil {
            break
        }

        reader := bytes.NewReader(data)

        if err := zssz.Decode(reader, uint64(len(data)), &state, phase0.BeaconStateSSZ); err != nil {
            panic(fmt.Sprintf("Cannot decode prestate %v: %v", filename, err))
        }


        PreloadedStates = append(PreloadedStates, state)

        fmt.Printf("Loaded and decoded prestate %v\n", filename)

        stateID++
    }

    if stateID == 0 {
        panic("No prestates found")
    }
}

func init() {
    {
        stateBlockSSZType_, err := types.SSZFactory(reflect.TypeOf(new(InputStateBlock)).Elem())
        if err != nil {
            panic("Could not create object from factory")
        }
        stateBlockSSZType = stateBlockSSZType_
    }

    {
        blockWrapperSSZType_, err := types.SSZFactory(reflect.TypeOf(new(InputBlockWrapper)).Elem())
        if err != nil {
            panic("Could not create object from factory")
        }
        blockWrapperSSZType = blockWrapperSSZType_
    }

    loadPrestates()
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

// TODO should this be a pointer or are we actually meaning to pass a copy?
func CheckInvariants(state phase0.BeaconState, correct bool) error {
    /* Balances and ValidatorRegistry must be the same length */
    // TODO to use fullfeaturedstate instead of phase0.BeaconState?
    // how to get from beaconstate to meta?
    // TODO is this how its supposed to work?
    // perhaps use phase0.InitState instead? (in genesis)
    ffstate := phase0.NewFullFeaturedState(&state)
    if len(ffstate.RegistryState.Balances) != len(ffstate.RegistryState.Validators) {
        if correct == false {
            return fmt.Errorf("Balances/ValidatorRegistry length mismatch (%v and %v)", len(ffstate.RegistryState.Balances), len(ffstate.RegistryState.Validators))
        }
        for len(ffstate.RegistryState.Balances) < len(ffstate.RegistryState.Validators) {
            ffstate.RegistryState.Balances = append(ffstate.RegistryState.Balances, 0)
        }
        for len(ffstate.RegistryState.Validators) < len(ffstate.RegistryState.Balances) {
            var tmp validator.Validator
            ffstate.RegistryState.Validators = append(ffstate.RegistryState.Validators, &tmp)
        }
    }

    /* Avoid division by zero in ProcessBlockHeader */
    {
        epoch := ffstate.VersioningState.CurrentEpoch()
        committeesPerSlot := ffstate.GetCommitteeCount(epoch) / uint64(core.SLOTS_PER_EPOCH)
        offset := core.Shard(committeesPerSlot) * core.Shard(ffstate.Slot%core.SLOTS_PER_EPOCH)
        // TODO this typechecks but may not be correct/intended operation?
        shardStatus := ffstate.ShardRotFeature.LoadStartShardStatus(epoch)
        shard := (shardStatus.GetStartShard(epoch) + offset) % core.SHARD_COUNT
        shuffleStatus := ffstate.LoadShufflingStatus()
        firstCommittee := shuffleStatus.GetCrosslinkCommittee(epoch, shard)
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

func CorrectInvariants(state phase0.BeaconState) {
    if err := CheckInvariants(state, true); err != nil {
        panic("CheckInvariants failed")
    }
}

func AssertInvariants(state phase0.BeaconState) {
    if err := CheckInvariants(state, false); err != nil {
        panic(fmt.Sprintf("Invariant check failed: %v", err))
    }
}

func decodeOfType(data []byte, dest interface{}, fuzzer bool, sszType types.SSZ) error {
    reader := bytes.NewReader(data)
    if fuzzer == true {
        if _, err := zssz.DecodeFuzzBytes(reader, uint64(len(data)), dest, sszType); err != nil {
            return errors.New("Cannot decode")
        }
    } else {
        if err := zssz.Decode(reader, uint64(len(data)), dest, sszType); err != nil {
            panic(fmt.Sprintf("Decoding that should always succeed failed: %v", err))
        }
    }

    return nil
}

func Decode(data []byte, dest interface{}, fuzzer bool) error {
    return decodeOfType(data, dest, fuzzer, *getSSZType(dest))
}

func DecodeAttestation(data []byte, fuzzer bool) (InputAttestation, error) {
    var input InputAttestation
    err := Decode(data, &input, fuzzer);
    return input, err
}

func DecodeAttesterSlashing(data []byte, fuzzer bool) (InputAttesterSlashing, error) {
    var input InputAttesterSlashing
    err := Decode(data, &input, fuzzer);
    return input, err
}

func DecodeBlockHeader(data []byte, fuzzer bool) (InputBlockHeader, error) {
    var input InputBlockHeader
    err := Decode(data, &input, fuzzer);
    return input, err
}

func DecodeDeposit(data []byte, fuzzer bool) (InputDeposit, error) {
    var input InputDeposit
    err := Decode(data, &input, fuzzer);
    return input, err
}

func DecodeTransfer(data []byte, fuzzer bool) (InputTransfer, error) {
    var input InputTransfer
    err := Decode(data, &input, fuzzer);
    return input, err
}

func DecodeVoluntaryExit(data []byte, fuzzer bool) (InputVoluntaryExit, error) {
    var input InputVoluntaryExit
    err := Decode(data, &input, fuzzer);
    return input, err
}

func DecodeProposerSlashing(data []byte, fuzzer bool) (InputProposerSlashing, error) {
    var input InputProposerSlashing
    err := Decode(data, &input, fuzzer);
    return input, err
}

func decodeBlockWrapper(data []byte, fuzzer bool) (InputBlockWrapper, error) {
    var input InputBlockWrapper
    err := decodeOfType(data, &input, fuzzer, blockWrapperSSZType);
    return input, err
}

func DecodeStateBlock(data []byte, fuzzer bool) (InputStateBlock, error) {
    var input InputStateBlock
    err := Decode(data, &input, fuzzer);
    return input, err
}

func DecodeBlockWrapper(data []byte, fuzzer bool) (InputBlockWrapper, error) {
    var input InputBlockWrapper
    err := Decode(data, &input, fuzzer);
    return input, err
}

func encodeOfType(src interface{}, sszType types.SSZ) []byte {
    var ret bytes.Buffer
    writer := bufio.NewWriter(&ret)
    // TODO can handle the number of bytes written if an error occurs?
    if _, err := zssz.Encode(writer, src, sszType); err != nil {
        panic("Cannot encode")
    }
    if err := writer.Flush(); err != nil {
        panic("Cannot flush encoded output")
    }

    return ret.Bytes()
}

func Encode(src interface{}) []byte {
    return encodeOfType(src, *getSSZType(src))
}

func EncodeState(state phase0.BeaconState) []byte {
    return encodeOfType(&state, phase0.BeaconStateSSZ)
}

func EncodePoststate(state phase0.BeaconState) []byte {
    AssertInvariants(state)

    return EncodeState(state)
}

// TODO should this return a pointer to the state, or are we wanting a new copy
// created?
func GetStateByID(stateID uint32) (phase0.BeaconState, error) {
    var state phase0.BeaconState
    if stateID >= uint32(len(PreloadedStates)) {
        return state, fmt.Errorf("Invalid prestate ID")
    }

    return PreloadedStates[stateID], nil
}

func randomlyValid(valid []byte, random []byte, chance float32) {
	chanceRNG := binary.LittleEndian.Uint32(random[:4])
	bit := random[4]
	// make random all valid
	copy(random, valid)
	v := float32(float64(chanceRNG) / float64(^uint32(0)))
	// now mutate random bit based on chance
	if v > chance || chance == 0 {
		random[bit >> 3] ^= 1 << (bit & 0x7)
	}
}

func correctBlock(state phase0.BeaconState, block *phase0.BeaconBlock) {
    {
        block.Slot = state.Slot + (block.Slot % 10)
    }

    {
        latestHeaderCopy := state.LatestBlockHeader
        latestHeaderCopy.StateRoot = zrnt_ssz.HashTreeRoot(state, phase0.BeaconStateSSZ)
        prevRoot := zrnt_ssz.SigningRoot(latestHeaderCopy, header.BeaconBlockHeaderSSZ)
        randomlyValid(prevRoot[:], block.ParentRoot[:], 0.9)
    }

    {
        for i := 0; i < len(block.Body.Attestations); i++ {
            data := &block.Body.Attestations[i].Data
            if data.Crosslink.Shard < core.Shard(len(state.CurrentCrosslinks)) {
                previousCrosslinkRoot := zrnt_ssz.HashTreeRoot(state.CurrentCrosslinks[data.Crosslink.Shard], crosslinks.CrosslinkSSZ)
                randomlyValid(previousCrosslinkRoot[:], data.Crosslink.ParentRoot[:], 0.9)
            }
        }
    }
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
        input, err := DecodeAttestation(data, true)
        if err == nil {
            CorrectInvariants(input.Pre)
            g_return_data = Encode(input)
            return len(g_return_data)
        }
        return 0
    case    INPUT_TYPE_ATTESTER_SLASHING:
        input, err := DecodeAttesterSlashing(data, true)
        if err == nil {
            CorrectInvariants(input.Pre)
            g_return_data = Encode(input)
            return len(g_return_data)
        }
        return 0
    case    INPUT_TYPE_BLOCK_HEADER:
        input, err := DecodeBlockHeader(data, true)
        if err == nil {
            CorrectInvariants(input.Pre)
            if err := CheckInvariants(input.Pre, false); err != nil {
                return 0
            }

            /* BlockHeader-specific invariants */
            {
                input.Block.ParentRoot = zrnt_ssz.SigningRoot(input.Pre.LatestBlockHeader, header.BeaconBlockHeaderSSZ)
            }

            g_return_data = Encode(input)
            return len(g_return_data)
        }
        return 0
    case    INPUT_TYPE_DEPOSIT:
        input, err := DecodeDeposit(data, true)
        if err == nil {
            CorrectInvariants(input.Pre)
            g_return_data = Encode(input)
            return len(g_return_data)
        }
        return 0
    case    INPUT_TYPE_TRANSFER:
        input, err := DecodeTransfer(data, true)
        if err == nil {
            CorrectInvariants(input.Pre)
            g_return_data = Encode(input)
            return len(g_return_data)
        }
        return 0
    case    INPUT_TYPE_VOLUNTARY_EXIT:
        input, err := DecodeVoluntaryExit(data, true)
        if err == nil {
            CorrectInvariants(input.Pre)
            g_return_data = Encode(input)
            return len(g_return_data)
        }
        return 0
    case    INPUT_TYPE_PROPOSER_SLASHING:
        input, err := DecodeProposerSlashing(data, true)
        if err == nil {
            CorrectInvariants(input.Pre)
            g_return_data = Encode(input)
            return len(g_return_data)
        }
        return 0
    case    INPUT_TYPE_BLOCK_WRAPPER:
        blockWrapper, err := decodeBlockWrapper(data, true)
        if err != nil {
            return 0
        }

        state, err := GetStateByID(blockWrapper.StateID)
        if err != nil {
            return 0
        }

        /*
        var stateBlock InputStateBlock

        stateBlock.State = state
        stateBlock.Block = blockWrapper.Block

        correctBlock(stateBlock.State, &stateBlock.Block)

        g_return_data = encodeOfType(stateBlock, stateBlockSSZType)
        */
        correctBlock(state, &blockWrapper.Block)
        g_return_data = encodeOfType(blockWrapper, blockWrapperSSZType)
        return len(g_return_data)
    default:
        panic("Invalid type configured")
    }
}

func GetStateBlock(data []byte) (InputStateBlock, error) {
    var stateBlock InputStateBlock

    blockWrapper, err := decodeBlockWrapper(data, true)
    if err != nil {
        return stateBlock, fmt.Errorf("Cannot decode blockwrapper")
    }

    state, err := GetStateByID(blockWrapper.StateID)
    if err != nil {
        return stateBlock, fmt.Errorf("Cannot decode blockwrapper")
    }

    stateBlock.State = state
    stateBlock.Block = blockWrapper.Block

    correctBlock(stateBlock.State, &stateBlock.Block)

    return stateBlock, nil
}
