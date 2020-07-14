## color
RED='\033[0;31m'
NC='\033[0m' # No Color

# find lighthouse crashes
echo "${RED}[lighthouse/hfuzz] crashes${NC}"
find hfuzz/hfuzz_workspace/* -iname '*.fuzz'
echo
echo "${RED}[lighthouse/libfuzzer] crashes${NC}"
find libfuzzer/fuzz/artifacts -iname 'crash-*'
echo
# TODO
# echo "${RED}[lighthouse/afl] crashes${NC}"
# find libfuzzer/fuzz/artifacts/ -type d -name "lighthouse_*" -exec find {} -iname 'id*' \;
# echo


# find prysm crashes
echo "${RED}[prysm] crashes${NC}"
find gofuzz/ -iname 'crash-*'
echo

# find nimbus crashes
echo "${RED}[nimbus] crashes${NC}"
find nimlibfuzzer/ -iname 'crash-*'
echo

# find teku crashes
echo "${RED}[teku] crashes${NC}"
find javafuzz/out_teku_attestation/ -type d -name "crashes*" -exec find {} -iname 'id*' \;
find javafuzz/out_teku_block_header/ -type d -name "crashes*" -exec find {} -iname 'id*' \;
find javafuzz/out_teku_proposer_slashing/ -type d -name "crashes*" -exec find {} -iname 'id*' \;
find javafuzz/out_teku_attester_slashing/ -type d -name "crashes*" -exec find {} -iname 'id*' \;
find javafuzz/out_teku_bls/ -type d -name "crashes*" -exec find {} -iname 'id*' \;
find javafuzz/out_teku_voluntary_exit/ -type d -name "crashes*" -exec find {} -iname 'id*' \;
find javafuzz/out_teku_block/ -type d -name "crashes*" -exec find {} -iname 'id*' \;
find javafuzz/out_teku_deposit/ -type d -name "crashes*" -exec find {} -iname 'id*' \;
echo

# find lodestar crashes
echo "${RED}[lodestar] crashes${NC}"
ls jsfuzz/crash-*
echo