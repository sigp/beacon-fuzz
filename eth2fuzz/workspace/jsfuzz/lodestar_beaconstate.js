var fuzz_targets = require("../targets/js/lib.js");

function fuzz(data) {
    fuzz_targets.fuzz_lodestar_beaconstate(data);
}

module.exports = {
    fuzz
};