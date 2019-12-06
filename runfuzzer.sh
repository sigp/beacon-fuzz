#!/bin/bash

if [ "$#" -lt 3 ]; then
    echo "Specify the fuzzer you want to run, the fuzzer corpus directory, and the state corpus directory."
    echo "Any additional arguments are passed to the fuzzer."
    exit 1
fi

FUZZER_CORPUS="$(realpath -e "$2")"
STATE_CORPUS_PATH="$(realpath -e "$3")"

# Ensure we are in the same directory as this script (the project root).
cd "$(dirname "${BASH_SOURCE[0]}")" || exit

# Check that $1 points to an actual fuzzing target
if [[ -z "$1" || (! -d "./files/fuzzers/$1") ]]; then
    echo "First argument must point to a valid fuzzing target."
    exit 1
fi

# Weird bash arcanery "PARAMETER EXPANSION" to pass quoted remaining args
tmp=("${@@Q}")
REMAINING_ARGS="${tmp[*]:3}"

docker build . -t eth2-fuzzers || exit

docker run \
    -v "$FUZZER_CORPUS":/eth2/corpus \
    -v "$STATE_CORPUS_PATH":/eth2/state-corpus \
    -t eth2-fuzzers /bin/sh -c \
    "export ETH2_FUZZER_STATE_CORPUS_PATH=/eth2/state-corpus && /eth2/fuzzers/\"$1\"/fuzzer /eth2/corpus $REMAINING_ARGS"
