#!/bin/bash

if [ "$#" -lt 1 ]
then
    echo "Specify the fuzzer you want to run"
    exit 1
fi

docker build . -t eth2-fuzzers

mkdir -p corpora

docker run -v `realpath corpora`:/eth2/corpora -t eth2-fuzzers /bin/sh -c "mkdir -p /eth2/corpora/$1 && /eth2/fuzzers/$1/fuzzer /eth2/corpora/$1 $2"
