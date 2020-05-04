# cardano-crypto-praos

This package implements Haskell FFI wrappers around the VRF (verifyable random
function) implemented in libsodium.

## Libsodium Dependency

This package depends on a custom fork of the `libsodium` C library, found at

https://github.com/input-output-hk/libsodium/tree/tdammers/rebased-vrf

### Usage with `cabal`:

- Clone out the above-mentioned libsodium fork
- Build and install this `libsodium` version (make sure `pkgconfig` can find
  it)
- Cabal should now pick up this version

### Usage with Nix:

TODO
