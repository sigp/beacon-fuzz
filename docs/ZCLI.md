# ZCLI

[github](https://github.com/protolambda/zcli)

Install:
``` sh
go get -tags preset_mainnet github.com/protolambda/zcli

./bin/zcli
```

# ZRNT

A minimal Go implementation of the ETH 2.0 spec - [github](https://github.com/protolambda/zrnt)

Fuzzing implementation with [eth2.0-fuzzing](https://github.com/guidovranken/eth2.0-fuzzing/)

## ZSSZ

"ZSSZ", a.k.a. ZRNT-SSZ, is the SSZ version used and maintained for ZRNT, the ETH 2.0 Go executable spec. - [github](https://github.com/protolambda/zssz)

## Installation (for v0.10.1)

- update GOPATH for current dir

``` sh
export GOPATH=$(pwd)
mkdir src
```

Install:
``` sh
go get github.com/protolambda/zrnt
cd src/github.com/protolambda/zrnt && git checkout v0.10.1

## get zrnt dependency
go get github.com/herumi/bls-eth-go-binary/
```

go-fuzz
``` sh
GO111MODULE=on go install -tags preset_mainnet ./...

go-fuzz-build --tags preset_mainnet github.com/protolambda/zrnt

```
