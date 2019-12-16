#!/bin/bash
# runs fuzzer endpoint with relevant env variables and shared libraries linked
# to be placed in the root of

HERE="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

FUZZER_EXECUTABLE="$HERE"/fuzzers/shuffle/fuzzer

export LD_LIBRARY_PATH="$HERE"/cpython-install/lib/python3.8/config-3.8-x86_64-linux-gnu:"$HERE"/cpython-install/lib/:"$HERE"/lib
export ETH2_FUZZER_STATE_CORPUS_PATH="$HERE"/beaconstate_corpora

"$FUZZER_EXECUTABLE" "$@"

LD_LIBRARY_PATH=cpython-install/lib/python3.8/config-3.8-x86_64-linux-gnu:cpython-install/lib/:./lib
ETH2_FUZZER_STATE_CORPUS_PATH=beaconstate_corpora
