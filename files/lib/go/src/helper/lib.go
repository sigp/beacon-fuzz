package helper

import "C"

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"reflect"

	"github.com/protolambda/zrnt/eth2/beacon/attestations"
	"github.com/protolambda/zrnt/eth2/beacon/deposits"
	"github.com/protolambda/zrnt/eth2/beacon/exits"
	"github.com/protolambda/zrnt/eth2/beacon/header"
	"github.com/protolambda/zrnt/eth2/beacon/slashings/attslash"
	"github.com/protolambda/zrnt/eth2/beacon/slashings/propslash"
	"github.com/protolambda/zrnt/eth2/beacon/validator"
	"github.com/protolambda/zrnt/eth2/core"
	"github.com/protolambda/zrnt/eth2/phase0"
	zrnt_ssz "github.com/protolambda/zrnt/eth2/util/ssz"
	"github.com/protolambda/zssz"
	"github.com/protolambda/zssz/types"
)

type InputType uint64

const (
	INPUT_TYPE_INVALID InputType = iota
	INPUT_TYPE_ATTESTATION
	INPUT_TYPE_ATTESTER_SLASHING
	INPUT_TYPE_BLOCK_HEADER
	INPUT_TYPE_DEPOSIT
	INPUT_TYPE_VOLUNTARY_EXIT
	INPUT_TYPE_PROPOSER_SLASHING
	INPUT_TYPE_BLOCK
)

var curInputType InputType = INPUT_TYPE_INVALID

// TODO I hate having to copy paste all this, but no generic functions/types
// is there 1 function I can do that will convert from these types to
// types with states?
// I think not, would have to return a more deeply embedded struct with similar members
// which might not serialize in the same way?
// or can I have them both serialize similarly?
//type InputWrapper struct {
//        StateID uint16
//        Other interface{}
//}

// TODO move types to separate file

// Input passed to implementations after preprocessing
type InputAttestation struct {
	Pre         phase0.BeaconState
	Attestation attestations.Attestation
}

type InputAttesterSlashing struct {
	Pre              phase0.BeaconState
	AttesterSlashing attslash.AttesterSlashing
}

type InputDeposit struct {
	Pre     phase0.BeaconState
	Deposit deposits.Deposit
}

type InputVoluntaryExit struct {
	Pre  phase0.BeaconState
	Exit exits.SignedVoluntaryExit
}

type InputProposerSlashing struct {
	Pre              phase0.BeaconState
	ProposerSlashing propslash.ProposerSlashing
}

type InputBlockHeader struct {
	Pre   phase0.BeaconState
	Block phase0.BeaconBlock
}

type InputBlock struct {
	Pre         phase0.BeaconState
	SignedBlock phase0.SignedBeaconBlock
}

// Types to be read from fuzzer
type InputBlockWrapper struct {
	StateID     uint16
	SignedBlock phase0.SignedBeaconBlock
}

// NOTE: not signed like Block is
type InputBlockHeaderWrapper struct {
	StateID uint16
	Block   phase0.BeaconBlock
}

type InputAttestationWrapper struct {
	StateID     uint16
	Attestation attestations.Attestation
}

type InputAttesterSlashingWrapper struct {
	StateID          uint16
	AttesterSlashing attslash.AttesterSlashing
}

type InputDepositWrapper struct {
	StateID uint16
	Deposit deposits.Deposit
}

type InputVoluntaryExitWrapper struct {
	StateID uint16
	Exit    exits.SignedVoluntaryExit
}

type InputProposerSlashingWrapper struct {
	StateID          uint16
	ProposerSlashing propslash.ProposerSlashing
}

// NOTE I think we want to avoid embedding here to ensure consistent serialization,
// so have all these functions

// TODO change to pointers to avoid copying? e.g. InputBlock struct { ... *phase0.BeaconBlock }
// I think that might screw with current serialization etc
func (w *InputBlockWrapper) unwrap() (*InputBlock, error) {
	state, err := GetStateByID(w.StateID)
	if err != nil {
		return nil, err
	}
	return &InputBlock{Pre: state, SignedBlock: w.SignedBlock}, nil
}

func (w *InputBlockHeaderWrapper) unwrap() (*InputBlockHeader, error) {
	state, err := GetStateByID(w.StateID)
	if err != nil {
		return nil, err
	}
	return &InputBlockHeader{Pre: state, Block: w.Block}, nil
}

func (w *InputAttestationWrapper) unwrap() (*InputAttestation, error) {
	state, err := GetStateByID(w.StateID)
	if err != nil {
		return nil, err
	}
	return &InputAttestation{Pre: state, Attestation: w.Attestation}, nil
}

func (w *InputAttesterSlashingWrapper) unwrap() (*InputAttesterSlashing, error) {
	state, err := GetStateByID(w.StateID)
	if err != nil {
		return nil, err
	}
	return &InputAttesterSlashing{Pre: state, AttesterSlashing: w.AttesterSlashing}, nil
}

func (w *InputDepositWrapper) unwrap() (*InputDeposit, error) {
	state, err := GetStateByID(w.StateID)
	if err != nil {
		return nil, err
	}
	return &InputDeposit{Pre: state, Deposit: w.Deposit}, nil
}

func (w *InputVoluntaryExitWrapper) unwrap() (*InputVoluntaryExit, error) {
	state, err := GetStateByID(w.StateID)
	if err != nil {
		return nil, err
	}
	return &InputVoluntaryExit{Pre: state, Exit: w.Exit}, nil
}

func (w *InputProposerSlashingWrapper) unwrap() (*InputProposerSlashing, error) {
	state, err := GetStateByID(w.StateID)
	if err != nil {
		return nil, err
	}
	return &InputProposerSlashing{Pre: state, ProposerSlashing: w.ProposerSlashing}, nil
}

var PreloadedStates = make([]phase0.BeaconState, 0)

// used internally by getSSZType
var sszTypeCache = make(map[reflect.Type]types.SSZ)

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
	loadPrestates()
}

func SetInputType(inputType_ InputType) {
	curInputType = inputType_
}

// NOTE: as input types do not necessarily have a unique `String()` representation,
// generally not an issue
// TODO add checks to avoid corruption
// thanks to https://stackoverflow.com/a/55321744
// dest should be a pointer to a value we want the associated SSZ type for
// NOTE: will panic if argument is not a pointer type
func getSSZType(dest interface{}) types.SSZ {

	t := reflect.TypeOf(dest).Elem()

	r, set := sszTypeCache[t]
	if set == true {
		return r
	}

	ssztyp := zssz.GetSSZ(dest)
	sszTypeCache[t] = ssztyp
	return ssztyp
}

// NOTE we couldn't actually correct/modify any changes if passing a copy of the struct
func CheckInvariants(state *phase0.BeaconState, correct bool) error {
	if correct == true {
		// need to have at least as many validators as slots per epoch
		// TODO initState requires this (why?)
		for core.Slot(len(state.Validators)) < core.SLOTS_PER_EPOCH {
			var tmp validator.Validator
			state.RegistryState.Validators = append(state.RegistryState.Validators, &tmp)
		}
	}
	/* Balances and ValidatorRegistry must be the same length */
	if len(state.RegistryState.Balances) != len(state.RegistryState.Validators) {
		if correct == false {
			return fmt.Errorf("Balances/ValidatorRegistry length mismatch (%v and %v)", len(state.RegistryState.Balances), len(state.RegistryState.Validators))
		}
		for len(state.RegistryState.Balances) < len(state.RegistryState.Validators) {
			state.RegistryState.Balances = append(state.RegistryState.Balances, 0)
		}
		for len(state.RegistryState.Validators) < len(state.RegistryState.Balances) {
			var tmp validator.Validator
			state.RegistryState.Validators = append(state.RegistryState.Validators, &tmp)
		}
	}

	depIndex := state.DepIndex()
	depCount := state.DepCount()
	if depIndex > depCount {
		if correct == false {
			return fmt.Errorf("DepositIndex greater than DepositCount (%v > %v), should be <=", depIndex, depCount)
		}
		// Set to equal, which is ok - says all deposits have been processed
		state.Eth1State.DepositIndex = depCount
	}

	// TODO
	// ensure committeeCount <= uint64(SHARD_COUNT)

	// TODO ensure number of active validators > committeeCount for current, prev and next epoch
	// NOTE: because committeeCount is calculated based on num active validators,
	// we just need to ensure that some validators are active?
	// based on zrnt validator.go CommitteeCount, we need to ensure number of active validators
	// is greater than SLOTS_PER_EPOCH

	/*
		    // NOTE: Not currently used
			ffstate := phase0.NewFullFeaturedState(state)
			ffstate.LoadPrecomputedData()
	*/

	/*
		    // TODO(gnattishness) check whether any of this is worth using
		    // not useful while we use trusted states as input
		    // relied on GetCrosslinkCommitee (not present in 0.9.x), but can't
		    // see any division by 0 that this would resolve

		    // I think unnecessary:
		    // get_beacon_proposer_index used to call get_crosslink_committee and `%` by its length
		    // resulting in div by 0, where now (0.9.1) compute_proposer_index checks the length

			// Avoid division by zero in ProcessBlockHeader
			{
				epoch := ffstate.VersioningState.CurrentEpoch()
				committeesPerSlot := ffstate.GetCommitteeCount(epoch) / uint64(core.SLOTS_PER_EPOCH)
				offset := core.Shard(committeesPerSlot) * core.Shard(ffstate.Slot%core.SLOTS_PER_EPOCH)
				// TODO this typechecks but may not be correct/intended operation?
				shard := (ffstate.GetStartShard(epoch) + offset) % core.SHARD_COUNT
		        // TODO now takes in a slot and index
				firstCommittee := ffstate.ShufflingStatus.GetBeaconCommitee(epoch, shard)
				if len(firstCommittee) == 0 {
					if correct == false {
						return errors.New("Empty firstCommittee")
					} else {
						// TODO correct
					}
				}
			}
	*/

	return nil
}

func CorrectInvariants(state *phase0.BeaconState) {
	if err := CheckInvariants(state, true); err != nil {
		panic(fmt.Sprintf("CorrectInvariants failed: %v", err))
	}
}

func AssertInvariants(state *phase0.BeaconState) {
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

func Decode(data []byte, destPtr interface{}, fuzzer bool) error {
	return decodeOfType(data, destPtr, fuzzer, getSSZType(destPtr))
}

func DecodeAttestation(data []byte, fuzzer bool) (*InputAttestation, error) {
	var input InputAttestation
	err := Decode(data, &input, fuzzer)
	return &input, err
}

func DecodeAttesterSlashing(data []byte, fuzzer bool) (*InputAttesterSlashing, error) {
	var input InputAttesterSlashing
	err := Decode(data, &input, fuzzer)
	return &input, err
}

func DecodeBlockHeader(data []byte, fuzzer bool) (*InputBlockHeader, error) {
	var input InputBlockHeader
	err := Decode(data, &input, fuzzer)
	return &input, err
}

func DecodeDeposit(data []byte, fuzzer bool) (*InputDeposit, error) {
	var input InputDeposit
	err := Decode(data, &input, fuzzer)
	return &input, err
}

func DecodeVoluntaryExit(data []byte, fuzzer bool) (*InputVoluntaryExit, error) {
	var input InputVoluntaryExit
	err := Decode(data, &input, fuzzer)
	return &input, err
}

func DecodeProposerSlashing(data []byte, fuzzer bool) (*InputProposerSlashing, error) {
	var input InputProposerSlashing
	err := Decode(data, &input, fuzzer)
	return &input, err
}

func DecodeBlock(data []byte, fuzzer bool) (*InputBlock, error) {
	var input InputBlock
	err := Decode(data, &input, fuzzer)
	return &input, err
}

// Wrapper Decoding
func DecodeBlockWrapper(data []byte, fuzzer bool) (*InputBlockWrapper, error) {
	var input InputBlockWrapper
	err := Decode(data, &input, fuzzer)
	return &input, err
}

func DecodeBlockHeaderWrapper(data []byte, fuzzer bool) (*InputBlockHeaderWrapper, error) {
	var input InputBlockHeaderWrapper
	err := Decode(data, &input, fuzzer)
	return &input, err
}

func DecodeAttestationWrapper(data []byte, fuzzer bool) (*InputAttestationWrapper, error) {
	var input InputAttestationWrapper
	err := Decode(data, &input, fuzzer)
	return &input, err
}

func DecodeAttesterSlashingWrapper(data []byte, fuzzer bool) (*InputAttesterSlashingWrapper, error) {
	var input InputAttesterSlashingWrapper
	err := Decode(data, &input, fuzzer)
	return &input, err
}

func DecodeDepositWrapper(data []byte, fuzzer bool) (*InputDepositWrapper, error) {
	var input InputDepositWrapper
	err := Decode(data, &input, fuzzer)
	return &input, err
}

func DecodeVoluntaryExitWrapper(data []byte, fuzzer bool) (*InputVoluntaryExitWrapper, error) {
	var input InputVoluntaryExitWrapper
	err := Decode(data, &input, fuzzer)
	return &input, err
}

func DecodeProposerSlashingWrapper(data []byte, fuzzer bool) (*InputProposerSlashingWrapper, error) {
	var input InputProposerSlashingWrapper
	err := Decode(data, &input, fuzzer)
	return &input, err
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

func Encode(srcPtr interface{}) []byte {
	return encodeOfType(srcPtr, getSSZType(srcPtr))
}

func EncodePoststate(state *phase0.BeaconState) []byte {
	AssertInvariants(state)

	return Encode(state)
}

// TODO should this return a pointer to the state, or are we wanting a new copy
// created?
func GetStateByID(stateID uint16) (phase0.BeaconState, error) {
	var state phase0.BeaconState
	if stateID >= uint16(len(PreloadedStates)) {
		return state, fmt.Errorf("Invalid prestate ID: %v", stateID)
	}

	return PreloadedStates[stateID], nil
}

func randomlyValid(valid []byte, random []byte, chance float32) {
	// NOTE: although "random" it is deterministically generated based on original input,
	// so repeatable
	chanceRNG := binary.LittleEndian.Uint32(random[:4])
	bit := random[4]
	// make random all valid
	copy(random, valid)
	v := float32(float64(chanceRNG) / float64(^uint32(0)))
	// now mutate random bit based on chance
	if v > chance || chance == 0 {
		random[bit>>3] ^= 1 << (bit & 0x7)
	}
}

func correctBlock(state *phase0.BeaconState, block *phase0.SignedBeaconBlock) {
	{
		block.Message.Slot = state.Slot + (block.Message.Slot % 10)
	}

	{
		latestHeaderCopy := state.LatestBlockHeader
		prevRoot := zrnt_ssz.HashTreeRoot(latestHeaderCopy, header.BeaconBlockHeaderSSZ)
		// TODO(gnattishness) evaluate if this is helpful - i feel if validation is turned on,
		// a mutation here will almost never be correct
		// This will also invalidate signatures
		randomlyValid(prevRoot[:], block.Message.ParentRoot[:], 0.9)
		// TODO block.state_root correction
	}

	// TODO eth1data??
}

var g_return_data = make([]byte, 0)

// TODO move external/"exported" functions to their own file

//export SSZPreprocessGetReturnData
func SSZPreprocessGetReturnData(return_data []byte) {
	// NOTE: for this to be correct, return_data must initially refer to an array with
	// the same size and capacity (i.e. that copy doesn't re-size the data)
	// Alternative could be to pass a pointer to a slice,
	// but generally don't want this memory to be managed by the go runtime/GC.
	if len(return_data) != len(g_return_data) {
		panic("return_data must be the same length as g_return_data.")
	}
	copy(return_data, g_return_data)
}

//export SSZPreprocess
func SSZPreprocess(data []byte) int {
	// returns relevant "unwrapped" type
	switch curInputType {
	case INPUT_TYPE_ATTESTATION:
		wrapped, err := DecodeAttestationWrapper(data, true)
		if err != nil {
			return 0
		}
		input, err := wrapped.unwrap()
		if err != nil {
			return 0
		}
		CorrectInvariants(&input.Pre)
		if err := CheckInvariants(&input.Pre, false); err != nil {
			// TODO is this checking necessary if we have trusted state inputs?
			return 0
		}
		g_return_data = Encode(input)
		return len(g_return_data)
	case INPUT_TYPE_ATTESTER_SLASHING:
		wrapped, err := DecodeAttesterSlashingWrapper(data, true)
		if err != nil {
			return 0
		}
		input, err := wrapped.unwrap()
		if err != nil {
			return 0
		}
		CorrectInvariants(&input.Pre)
		if err := CheckInvariants(&input.Pre, false); err != nil {
			return 0
		}
		g_return_data = Encode(input)
		return len(g_return_data)
	case INPUT_TYPE_BLOCK_HEADER:
		wrapped, err := DecodeBlockHeaderWrapper(data, true)
		if err != nil {
			return 0
		}
		input, err := wrapped.unwrap()
		if err != nil {
			return 0
		}
		CorrectInvariants(&input.Pre)
		if err := CheckInvariants(&input.Pre, false); err != nil {
			return 0
		}

		/* BlockHeader-specific invariants */
		{
			// TODO make this randomly corrected?
			input.Block.ParentRoot = zrnt_ssz.HashTreeRoot(input.Pre.LatestBlockHeader, header.BeaconBlockHeaderSSZ)
		}

		g_return_data = Encode(input)
		return len(g_return_data)
	case INPUT_TYPE_DEPOSIT:
		wrapped, err := DecodeDepositWrapper(data, true)
		if err != nil {
			return 0
		}
		input, err := wrapped.unwrap()
		if err != nil {
			return 0
		}
		CorrectInvariants(&input.Pre)
		// This should ensure DepositIndex <= DepositCount
		if err := CheckInvariants(&input.Pre, false); err != nil {
			// TODO log error here? if we've corrected invariants, they should be correct
			return 0
		}
		// ensure that DepositIndex < DepositCount, to allow at least 1 deposit to be processed
		depCount := input.Pre.DepCount()
		if input.Pre.DepIndex() == depCount {
			if depCount == 0 {
				// need to add an entry to the deposits
				input.Pre.Eth1State.Eth1Data.DepositCount += 1
				// TODO discuss - either need to update the Merkle root here or ensure Merkle validation is disabled
			} else {
				// reduce the DepositIndex to protect the invariant
				input.Pre.Eth1State.DepositIndex -= 1
			}
		}
		g_return_data = Encode(input)
		return len(g_return_data)
	case INPUT_TYPE_VOLUNTARY_EXIT:
		wrapped, err := DecodeVoluntaryExitWrapper(data, true)
		if err != nil {
			return 0
		}
		input, err := wrapped.unwrap()
		if err != nil {
			return 0
		}
		CorrectInvariants(&input.Pre)
		if err := CheckInvariants(&input.Pre, false); err != nil {
			return 0
		}
		g_return_data = Encode(input)
		return len(g_return_data)
	case INPUT_TYPE_PROPOSER_SLASHING:
		wrapped, err := DecodeProposerSlashingWrapper(data, true)
		if err != nil {
			return 0
		}
		input, err := wrapped.unwrap()
		if err != nil {
			return 0
		}
		CorrectInvariants(&input.Pre)
		if err := CheckInvariants(&input.Pre, false); err != nil {
			return 0
		}
		g_return_data = Encode(input)
		return len(g_return_data)
	case INPUT_TYPE_BLOCK:
		wrapped, err := DecodeBlockWrapper(data, true)
		if err != nil {
			return 0
		}
		input, err := wrapped.unwrap()
		if err != nil {
			return 0
		}
		CorrectInvariants(&input.Pre)
		if err := CheckInvariants(&input.Pre, false); err != nil {
			return 0
		}
		// TODO update eth1data to match deposits?
		correctBlock(&input.Pre, &input.SignedBlock)
		g_return_data = Encode(input)
		return len(g_return_data)
	default:
		panic("Invalid type configured")
	}
}
