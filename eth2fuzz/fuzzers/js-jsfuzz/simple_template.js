var fuzz_targets = require("../targets/js/lib.js");

function fuzz(data) {
    fuzz_targets.fuzz_###TARGET###(data);
}

module.exports = {
    fuzz
};
