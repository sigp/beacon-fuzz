#!/bin/bash

if [ "$#" -lt 3 ]; then
    echo "Specify the fuzzer you want to run, the fuzzer corpus directory, and the state corpus directory"
    exit 1
fi

FUZZER_CORPUS=$(realpath "$2")
STATE_CORPUS_PATH=$(realpath "$3")

docker build . -t eth2-fuzzers

mkdir -p corpora

docker run \
    -v "$FUZZER_CORPUS":/eth2/corpus \
    -v "$STATE_CORPUS_PATH":/eth2/state-corpus \
    -t eth2-fuzzers /bin/sh -c \
    "export ETH2_FUZZER_STATE_CORPUS_PATH=/eth2/state-corpus && /eth2/fuzzers/\"$1\"/fuzzer /eth2/corpus $4"
