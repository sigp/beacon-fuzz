# Issues Found

A list of issues that have been found, includes false positives and notes.

Milagro:
- milagro_bls `AggregatePublicKey` will successfully deserialise [0; 48] as empty.
  - Don't use `AggregatePublicKey::from_bytes()`

BLST:
- blst does not check compressed points byte length are exact (can be twice required length).
  - Fixed: https://github.com/supranational/blst/issues/14
- blst does not enforce field elements less than the field modulus.
  - Fixed: https://github.com/supranational/blst/issues/15
- blst converts the point (0, +-2) to the point at infinity in `uncompress()`
  - Remaining as is see https://github.com/supranational/blst/issues/16

ZCash:
- zkcrypto does not check validity of sqaure root in `from_compressed()`.
  - May get a point that is not on the curve.
