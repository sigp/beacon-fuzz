# BLS Fuzz
Fuzz rust implementations of BLS12-381.

Current implementations
- [Milagro BLS](https://github.com/sigp/milagro_bls)
- [BLST](https://github.com/supranational/blst)
- [ZKCrypto](https://github.com/zkcrypto/bls12_381)

Future Implementations:
- [Herumi](https://github.com/herumi/bls-eth-rust)

## Running

Make sure the submodules are setup by running.

```bash
git submodule init && git submodule update
```

To run the fuzzers the following command can be run from this directory or subdirectories.

```bash
cargo fuzz run <fuzz_target>
```

The list of available fuzz targets that can be run are
- `fuzz_blst_serde_g1`
- `fuzz_blst_serde_g2`
- `fuzz_milagro_serde_g1`
- `fuzz_milagro_serde_g2`
- `fuzz_differential_serde_g1`
- `fuzz_differential_serde_g2`
- `fuzz_differential_add_g1`
- `fuzz_differential_add_g2`
- `fuzz_differential_mul_g1`
- `fuzz_differential_mul_g2`

## Notes

If you wish to update the BLST implementation change the commit in the submodule
`impls/blst`, then a modify the `Signature` struct to add
`#[derive(Default,...)`.
