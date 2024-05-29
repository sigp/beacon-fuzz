/*
name: lodestar
github: https://github.com/ChainSafe/lodestar
npm: https://www.npmjs.com/package/@chainsafe/lodestar

NOTES: you will need to install lodastar package using 
npm i @chainsafe/lodestar-types
*/

// TODO - improve to not only fuzz ssz parsing
// but also processing function
// need to deal with beaconstate and config loading

// state-transition
// https://github.com/ChainSafe/lodestar/tree/master/packages/lodestar-beacon-state-transition


function is_lodestar_valid_exception(e)  {
    // Those are "valid" exceptions. 
    if (e.name == "Error" ) {} 
    // following condition are temporary
    // waiting for fix of https://github.com/ChainSafe/ssz/issues/23
    // waiting for fix of https://github.com/ChainSafe/ssz/issues/22
    // else if (e.message == "Offset is outside the bounds of the DataView" ) {} 
    // else if (e.message == "Cannot convert undefined to a BigInt" ) {} 
    else {
        throw e;
    }

}


function fuzz_lodestar_attestation(buf) {
    var mainnet_1 = require("@chainsafe/lodestar-types/lib/presets/mainnet");
    try {
        mainnet_1.types.phase0.Attestation.deserialize(buf);
    } catch (e) {
        // verify if it's a valid exception
        is_lodestar_valid_exception(e);
    }
}

function fuzz_lodestar_attester_slashing(buf) {
    var mainnet_1 = require("@chainsafe/lodestar-types/lib/presets/mainnet");
    try {
        mainnet_1.types.phase0.AttesterSlashing.deserialize(buf);
    } catch (e) {
        is_lodestar_valid_exception(e);
    }
}


function fuzz_lodestar_block(buf) {
    var mainnet_1 = require("@chainsafe/lodestar-types/lib/presets/mainnet");
    try {
        mainnet_1.types.phase0.BeaconBlock.deserialize(buf);
    } catch (e) {
        is_lodestar_valid_exception(e);
    }
}

function fuzz_lodestar_block_header(buf) {
    var mainnet_1 = require("@chainsafe/lodestar-types/lib/presets/mainnet");
    try {
        mainnet_1.types.phase0.BeaconBlockHeader.deserialize(buf);
    } catch (e) {
        is_lodestar_valid_exception(e);
    }
}
function fuzz_lodestar_deposit(buf) {
    var mainnet_1 = require("@chainsafe/lodestar-types/lib/presets/mainnet");
    try {
        mainnet_1.types.phase0.Deposit.deserialize(buf);
    } catch (e) {
        is_lodestar_valid_exception(e);
    }
}
function fuzz_lodestar_proposer_slashing(buf) {
    var mainnet_1 = require("@chainsafe/lodestar-types/lib/presets/mainnet");
    try {
        mainnet_1.types.phase0.ProposerSlashing.deserialize(buf);
    } catch (e) {
        is_lodestar_valid_exception(e);
    }
}
function fuzz_lodestar_voluntary_exit(buf) {
    var mainnet_1 = require("@chainsafe/lodestar-types/lib/presets/mainnet");
    try {
        mainnet_1.types.phase0.VoluntaryExit.deserialize(buf);
    } catch (e) {
        is_lodestar_valid_exception(e);
    }
}

function fuzz_lodestar_beaconstate(buf) {
    var mainnet_1 = require("@chainsafe/lodestar-types/lib/presets/mainnet");
    try {
        mainnet_1.types.phase0.BeaconState.deserialize(buf);
    } catch (e) {
        is_lodestar_valid_exception(e);
    }
}

// Test parsing ENR base64 encoded string
// install with
// npm i @chainsafe/discv5
function fuzz_lodestar_enr(buf) {
    var discv5 = require("@chainsafe/discv5");
    try {
        discv5.ENR.decodeTxt(buf.toString());
    } catch (e) {
        // TODO
        if (e.name == "Error") {}
        //else if (e.message == "Cannot read property 'toString' of undefined") {}
        else {throw e;}
        //is_lodestar_valid_exception(e);
    }
}

module.exports = {
    fuzz_lodestar_attestation,
    fuzz_lodestar_attester_slashing,
    fuzz_lodestar_block,
    fuzz_lodestar_block_header,
    fuzz_lodestar_deposit,
    fuzz_lodestar_proposer_slashing,
    fuzz_lodestar_voluntary_exit,
    fuzz_lodestar_beaconstate,
    fuzz_lodestar_enr,
}
