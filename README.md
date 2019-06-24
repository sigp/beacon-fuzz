# eth2.0-fuzzing

This project and its inner workings are subject to change, but you can currently build and run the full state transition function fuzzer with these commands:

```
git clone --depth 1 https://github.com/guidovranken/eth2.0-fuzzing-corpora.git
git clone --depth 1 https://github.com/guidovranken/eth2.0-fuzzing.git
cd eth2.0-fuzzing
./runfuzzer.sh block ../eth2.0-fuzzing-corpora/block-v07-minimal ../eth2.0-fuzzing-corpora/state-corpus-v07-minimal
```
