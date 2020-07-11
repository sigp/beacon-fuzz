var discv5 = require("@chainsafe/discv5");
// var mainnet_1 = require("@chainsafe/lodestar-types/lib/ssz/presets/mainnet");

buf = Buffer.from('XXX', 'hex').toString()
// buf = Buffer.from('XXX', 'hex')

console.log(buf)

discv5.ENR.decodeTxt(buf);
// mainnet_1.types.BeaconBlock.deserialize(buf);