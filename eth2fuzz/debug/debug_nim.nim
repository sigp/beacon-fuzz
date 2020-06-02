import
  confutils, os, strutils, chronicles, json_serialization,
  ../beacon_chain/spec/crypto,
  ../beacon_chain/spec/datatypes,
  ../beacon_chain/spec/digest,
  ../beacon_chain/spec/validator,
  ../beacon_chain/spec/beaconstate,
  ../beacon_chain/spec/state_transition_block,
  ../beacon_chain/ssz,
  ../beacon_chain/extras,
  ../beacon_chain/state_transition,
  ../beacon_chain/eth2_discovery
# TODO turn into arguments
cli do(beacon: string, container: string):
  try :
    var b = SSZ.loadFile(beacon, BeaconState)
    var c = SSZ.loadFile(container, ProposerSlashing)
    var cache = get_empty_per_epoch_cache()
    discard process_proposer_slashing(b, c, {}, cache)
  except SSZError:
    quit 1
  quit 0

#  case kind
#  of "attester_slashing": printit(AttesterSlashing)
#  of "attestation": printit(Attestation)
#  of "block": printit(BeaconBlock)
#  of "block_body": printit(BeaconBlockBody)
#  of "block_header": printit(BeaconBlockHeader)
#  of "deposit": printit(Deposit)
#  of "deposit_data": printit(DepositData)
#  of "eth1_data": printit(Eth1Data)
#  of "state": printit(BeaconState)
#  of "proposer_slashing": printit(ProposerSlashing)
#  of "voluntary_exit": printit(VoluntaryExit)
#  else: echo "Unknown kind"
