#!/usr/bin/env bash
rm *.zip *.tar.* *.so cryptlib nettle libsodium jade rust
rm -rf cryptlib-3.4.6/ gmp-6.2.1/ libjade/ libsodium-1.0.18/ nettle-3.8/ gmp-6.2.1-1.src/
cd crypto/
cargo clean