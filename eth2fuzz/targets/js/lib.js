

// you will need to install lodastar package using 
// npm i @chainsafe/lodestar-types
function fuzz_lodestar_block(buf) {
    var mainnet_1 = require("@chainsafe/lodestar-types/lib/ssz/presets/mainnet");

    try {
        mainnet_1.types.BeaconBlock.deserialize(buf);
    } catch (e) {
        // Those are "valid" exceptions. we can't catch them in one line as
        if (e.message.indexOf('Offset out of bounds') !== -1 ||
            e.message.indexOf('Not all variable bytes consumed') !== -1 ) {
        } else {
            throw e;
        }
    }
}

module.exports = {
    fuzz_lodestar_block
}
