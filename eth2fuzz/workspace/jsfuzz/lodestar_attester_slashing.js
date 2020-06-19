var fuzz_targets = require("../targets/js/lib.js");

function fuzz(data) {
    fuzz_targets.fuzz_lodestar_attester_slashing(data);
}

module.exports = {
    fuzz
};
