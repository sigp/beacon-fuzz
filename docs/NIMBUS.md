# nim-beacon-chain

Implementation of Ethereum Sharded Casper v2.1 Beacon Chain - [github](https://github.com/status-im/nim-beacon-chain)

## Installation

```
$ git clone https://github.com/status-im/nim-beacon-chain

# Better to fuzz dev branch
$ git checkout devel

$ cd nim-beacon-chain

$ make # The first `make` invocation will update all Git submodules and prompt you to run `make` again.
       # It's only required once per Git clone. You'll run `make update` after each `git pull`, in the future,
       # to keep those submodules up to date.  

$ make 

$ make test
```

## compile ncli tool

``` sh
$ cd ncli

$ ../env.sh nim c -d:const_preset=mainnet ncli_pretty
```
