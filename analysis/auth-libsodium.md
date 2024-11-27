# auth-libsodium
The function `crypto_auth(out, in, inlen, key)` computes an authentication tag for the message `in`, whose length is `inlen` bytes, and the key `k`, which has a fixed length of 32 bytes. The result is stored in `out`, which should be at least 32 messages long. Official documentation can be found [here](https://libsodium.gitbook.io/doc/secret-key_cryptography/secret-key_authentication).

## Summary of the operations
In order to compute the tag, the function `crypto_auth(out, in, inlen, key)` has two sha512 contexts (it calculates two sha512 hashes), namely `ictx` and `octx` (from input and output contexts). It performs the following operations:

**crypto_auth_hmacsha512_init**:
1. `crypto_hash_sha512_init(ictx)`
2. `crypto_hash_sha512_update(ictx, key ^ 0x36, 128)`
3. `crypto_hash_sha512_init(octx)`
4. `crypto_hash_sha512_update(octx, key ^ 0x5c, 128)`

**crypto_auth_hmacsha512_update**:
1. `crypto_hash_sha512_update(ictx, in, inlen)`

**crypto_auth_hmacsha512256_final**:
1. `crypto_hash_sha512_final(ictx, inhash)`
2. `crypto_hash_sha512_update(octx, inhash, 64)`
3. `crypto_hash_sha512_final(octx, out)`

**Summary**: `hash(key^0x5c + hash(key^0x36 + in))`

## Silent Stores

#### TLDR
The operation `crypto_hash_sha512_update(ctx, in, inlen)` copies contents of `in` into an internal buffer `ctx->buf`. The `crypto_auth` algorithm performs `crypto_hash_sha512_update(ictx, key ^ 0x36, 128)`, which sets the buffer to the key xored with 0x36. It then performs `crypto_hash_sha512_update(ictx, in, inlen)`, which replaces the contents of the buffer with the message. Measuring silent stores in this operation will tell us if `in` matches `key ^ 0x36`, allowing an attacker that controls `in` to leak the secret `key`. A possible scenario would be a service that performs message authentication using a secret key, where the messages might be controlled by an attacker. You can see a simulation and exploitation of this scenario [here](../src/attack_auth_ssi.py). In this script we analyze the trace and, therefore, we assume an attacker that knows **which** program counters resulted in silent stores.


#### On both initialized and uninitialized memory
| Id | Count |                                                                                   Line                                                                                  |
|:--:|------:|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1  |   459 | `crypto_hash_sha512_update` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L233                      |
| 2  |   351 | `crypto_hash_sha512_update` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L238                      |
| 3  |   285 | `crypto_auth_hmacsha512_init` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_auth/hmacsha512/auth_hmacsha512.c#L54 (discriminator 3) |
| 4  |   285 | `crypto_auth_hmacsha512_init` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_auth/hmacsha512/auth_hmacsha512.c#L61 (discriminator 3) |
| 5  |   124 | `store64_be` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L165                                          |
| 6  |   111 | `store64_be` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L167                                          |
| 7  |   108 | `store64_be` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L168                                          |
| 8  |   103 | `store64_be` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L163                                          |
| 9  |   102 | `store64_be` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L166                                          |
| 10 |    99 | `store64_be` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L164                                          |
| 11 |    99 | `SHA512_Pad` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L181                                     |
| 12 |    98 | `store64_be` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L161                                          |
| 13 |    85 | `store64_be` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L162                                          |
| 14 |    48 | `__memset_sse2_unaligned_erms` at ??#L?                                                                                                                                 |
| 15 |    33 | `be64dec_vect` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L56                                    |
| 16 |    24 | `memset` at /usr/include/x86_64-linux-gnu/bits/string_fortified.h#L59                                                                                                   |

#### Just on initialized memory
| Id | Count |                                                                                   Line                                                                                  |
|:--:|------:|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1  |   566 | `crypto_hash_sha512_update` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L233                      |
| 2  |   202 | `SHA512_Pad` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L181                                     |
| 3  |   100 | `crypto_auth_hmacsha512_init` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_auth/hmacsha512/auth_hmacsha512.c#L54 (discriminator 3) |
| 4  |   100 | `crypto_auth_hmacsha512_init` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_auth/hmacsha512/auth_hmacsha512.c#L61 (discriminator 3) |
| 5  |    75 | `__memset_sse2_unaligned_erms` at ??#L?                                                                                                                                 |
| 6  |    70 | `store64_be` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L166                                          |
| 7  |    63 | `store64_be` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L167                                          |
| 8  |    58 | `store64_be` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L165                                          |
| 9  |    57 | `store64_be` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L168                                          |
| 10 |    53 | `store64_be` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L163                                          |
| 11 |    49 | `store64_be` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L164                                          |
| 12 |    49 | `store64_be` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L162                                          |
| 13 |    45 | `store64_be` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L161                                          |
| 14 |    24 | `memset` at /usr/include/x86_64-linux-gnu/bits/string_fortified.h#L59                                                                                                   |
| 15 |    18 | `be64dec_vect` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L56                                    |


Silent stores in `crypto_auth_hmacsha512_init` (entries 3 and 4) are doing `pad[i] ^= key[i]`, with `pad` initialised to 0x36 or 0x5c, which directly leaks which bytes of the key are 0.

There are two different silent stores in `crypto_hash_sha512_update`, which are copying `in` into `state->buf`. The one in [line 238](https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L238) (entry 2 in the first table) doesn't happen when tracking silent stores only on initialised memory. Therefore, those happen when `state->buf` has not been initialised, i.e. in the first two updates (`sha512_update(ictx, key ^ 0x36, 128)` and `update(octx, key ^ 0x5c, 128)`). This also makes sense with the size (128). Assuming `state->buf` initial content is nullbytes, I believe a silent store writing `key ^ 0x36` or `key ^ 0x5c` would leak which bytes of the key are 0x36 or 0x5c.

On the other hand, the silent stores in [line 233](https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L233) (entry 1) also happen when tracking silent stores only on initialised memory, which makes them more interesting. These happen in the calls `update(ictx, in, inlen)` and `update(octx, ihash, 64)`. This also makes sense with the size (for now our `inlen` is fixed to 16 < 128). Since `ictx->buf` is [now initialised](https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_auth/hmacsha512/auth_hmacsha512.c#L52) with `key ^ 0x36`, a silent store in `ictx->buf[i] = in[i]` could leak whether `key[i] ^ 0x36` matches `in[i]`, effectively **leaking the key**. On the other hand, a silent store in `octx->buf[i] = ihash[i]` could leak whether `key[i] ^ 0x5c` matches `ihash[i]`.

When trying to measure silent stores in `ictx->buf[i] = in[i]`, there are a number of noise silent stores that complicate leaking the key measuring just the length of the traces. Some are:
- `store64_be` when called from `be64enc_vect` when called from [here](https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_auth/hmacsha512/auth_hmacsha512.c#L86): when bytes of the input hash are 0
- `ictx->buf[i] = in[i]` in [here](https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L233) but when called from `crypto_auth_hmacsha512_final` : when bytes of the input hash match key ^ 0x5c
- `memset`

## Register File Compression
| Id |  Count  |                                                                             Line                                                                            |
|:--:|--------:|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1  | 1083640 | `rotr64` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L58 (discriminator 1)                 |
| 2  |  368726 | `rotr64` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L58 (discriminator 2)                 |
| 3  |   34444 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L127 (discriminator 1) |
| 4  |   34444 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L134 (discriminator 1) |
| 5  |   34443 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L128 (discriminator 1) |
| 6  |   34443 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L132 (discriminator 1) |
| 7  |   34443 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L136 (discriminator 1) |
| 8  |   34442 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L130 (discriminator 1) |
| 9  |   34442 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L133 (discriminator 1) |
| 10 |   34441 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L129 (discriminator 1) |
| 11 |   34441 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L131 (discriminator 1) |
| 12 |   34441 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L135 (discriminator 1) |
| 13 |   34430 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L126 (discriminator 1) |
| 14 |   34417 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L125 (discriminator 1) |
| 15 |   30998 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L123 (discriminator 1) |
| 16 |   30998 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L124 (discriminator 1) |
| 17 |   14365 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L143 (discriminator 2) |
| 18 |   13500 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L142 (discriminator 2) |
| 19 |   13207 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L144 (discriminator 2) |
| 20 |   13202 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L145 (discriminator 2) |
| 21 |   12645 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L141 (discriminator 2) |
| 22 |   12628 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L146 (discriminator 2) |
| 23 |   12628 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L147 (discriminator 2) |
| 24 |   11480 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L137 (discriminator 1) |
| 25 |   10335 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L122 (discriminator 1) |
| 26 |    9184 | `store64_be` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L162                              |
| 27 |    9184 | `store64_be` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L163                              |
| 28 |    9184 | `store64_be` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L164                              |
| 29 |    9184 | `store64_be` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L165                              |
| 30 |    9184 | `store64_be` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L166                              |
| 31 |    7462 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L151 (discriminator 2) |
| 32 |    7178 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L149 (discriminator 2) |
| 33 |    6888 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L148 (discriminator 2) |
| 34 |    6888 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L150 (discriminator 2) |
| 35 |    5740 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L154 (discriminator 2) |
| 36 |    5740 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L155 (discriminator 2) |
| 37 |    1148 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L152 (discriminator 2) |
| 38 |      34 | `store64_be` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L167                              |
| 39 |      19 | `load64_be` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L142                               |

## Narrow Register File Compression
| Id | Count |                                                                             Line                                                                            |
|:--:|------:|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1  |    68 | `rotr64` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L58 (discriminator 2)                 |
| 2  |    45 | `load64_be` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L142                               |
| 3  |    42 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L141 (discriminator 2) |
| 4  |    40 | `store64_be` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L165                              |
| 5  |    34 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L143 (discriminator 2) |
| 6  |    25 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L142 (discriminator 2) |

## Computation Simplification
| Id | Count |                                                                                   Line                                                                                  |
|:--:|------:|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1  |   127 | `crypto_auth_hmacsha512_init` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_auth/hmacsha512/auth_hmacsha512.c#L54 (discriminator 3) |
| 2  |   127 | `crypto_auth_hmacsha512_init` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_auth/hmacsha512/auth_hmacsha512.c#L61 (discriminator 3) |
| 3  |    18 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L141 (discriminator 2)             |
| 4  |    16 | `rotr64` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L58 (discriminator 2)                             |
| 5  |    16 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L143 (discriminator 2)             |
| 6  |    14 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L142 (discriminator 2)             |
| 7  |     4 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L122 (discriminator 1)             |
| 8  |     3 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L123 (discriminator 1)             |
| 9  |     3 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L125 (discriminator 1)             |
| 10 |     3 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L144 (discriminator 2)             |
| 11 |     2 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L124 (discriminator 1)             |

## Operand Packing
| Id | Count |                                                                             Line                                                                            |
|:--:|------:|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1  |     6 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L142 (discriminator 2) |
| 2  |     6 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L143 (discriminator 2) |
| 3  |     3 | `crypto_hash_sha512_update` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L224          |
| 4  |     3 | `crypto_hash_sha512_update` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L221          |
| 5  |     2 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L141 (discriminator 2) |
| 6  |     2 | `crypto_hash_sha512_update` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L250          |

## Computation Reuse
| Id | Count |                                                                                   Line                                                                                  |
|:--:|------:|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1  | 11520 | `crypto_auth_hmacsha512_init` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_auth/hmacsha512/auth_hmacsha512.c#L54 (discriminator 3) |
| 2  | 11520 | `crypto_auth_hmacsha512_init` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_auth/hmacsha512/auth_hmacsha512.c#L61 (discriminator 3) |
| 3  |     3 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L143 (discriminator 2)             |
| 4  |     2 | `rotr64` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L58 (discriminator 2)                             |

First two violations belong to a loop `pad[i] ^= key[i]`, where pad is initialised to a fixed value (`0x36` or `0x5c`). Since every byte of the key is xored with the same value, a CR would happen when `key` contains repeated bytes. The computation `key[i] ^ pad` would be reused for `key[j] ^ pad`, where `j > i, key[i] = key[j]`. Therefore, an attacker who is able to measure how many CRs happen would leak how many repeated bytes there are in `key`.

## Computation Reuse (keeping state of first input)
| Id | Count | Line                                                                                                                                                                    |
|:--:|------:|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1  |     1 | `crypto_auth_hmacsha512_init` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_auth/hmacsha512/auth_hmacsha512.c#L54 (discriminator 3) |
| 2  |     1 | `crypto_auth_hmacsha512_init` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_auth/hmacsha512/auth_hmacsha512.c#L61 (discriminator 3) |

CR is triggering in this kind of loops:
```c
memset(pad, 0x36, 128);
for (i = 0; i < keylen; i++) {
	pad[i] ^= key[i];
}
```

#### Threat Model 1
Let's assume a victim runs the previous code with its secret key. The Reuse Buffer (RB) is populated with the results of the operations. Then, an attacker runs the same code with its key, and his goal is to leak the victim key.

Since the XOR operation is performed at the same PC for every byte of the key, the Reuse Buffer contains an entry with operands `(0x36, key[i])` for each byte of the victim key. Therefore, when an attacker performs a subsequent execution with a controlled key, a CR in any iteration would mean that byte is also contained in the victim key. That would leak how many bytes of its key are also contained in the victim key. In particular, for each possible value in 0..255, the attacker can set every byte of its key to that value. At every iteration, the operation `value ^ 0x36` will be performed. For all iterations but the first, the computation will be reused. For the first iteration, it depends on whether `value` was present in the victim key. As a result, if the attacker measures `keylen` CRs, it means that value is present in the victim key. Otherwise, he would measure `keylen - 1` CRs, meaning that the value is not present in the victim key. This effectively leaks which bytes the victim key is composed of. However, I believe there's no way of leaking information about the position of those bytes. Since all entries in the RB are for the same PC, there is no information to leak related to the position of the bytes.

If the loop were unrolled, there would be a different entry in the RB for each byte of the key, and it would be possible for an attacker to leak the full key. However, if unrolling is applied, it's possible that also the xor operation is not performed byte by byte, but maybe in chunks of 4 or 8 bytes, difficulting the bruteforce. This depends on compiler optimizations.

#### Threat Model 2
Let's now assume the attacker runs first, populating the contents of the RB with arbitrary contents. Then, the victim runs with its secret key. The attacker, who is able to measure CRs, aims at leaking the victim key.

A CR in `key[i] ^ 0x36` would mean the byte `key[i]` of the victim key was also present in the attacker key. If the attacker uses a single fixed byte for its key, then it would leak that there's a byte in the victim key that matches that fixed byte. The problem is that we don't know which position it is. Since every CR is happening at the same address, we don't have a way to tell the iteration of the loop in which it happened just with the trace of CRs. We would need a stronger leakage model. Leaking whether a CR happened or not at each iteration would be enough.

There is a solution. Remember the loop is something like this:
```c
memset(pad, 0x36, 128);
for (i = 0; i < keylen; i++) {
	pad[i] ^= key[i];
}
```
When the victim runs, the `i++` operation is reused, because it was cached in the previous execution. This works as a separator between iterations, and can tell us exactly in which iteration the `key[i] ^ 0x36` CR happens, leaking the value of the key in that position. The idea is the following. The attacker sets every byte of its key to a fixed `value`, and runs the code. Then, the victim runs with its secret key. The attacker gets the trace of CRs, and can tell in which iteration happened. If CR triggered at iteration `i`, it leaks `key[i] = value`. Note that, in order to be able to reuse the `i++` computation, the Reuse Buffer must be able to save at least `keylen` computations per PC.

In addition, there's another problem. If the victim key contains repeated bytes, the first time the computation is performed it will be cached. Therefore, the following computations for the same byte will always trigger CR, no matter the initial state of the Reuse Buffer. This makes it impossible to leak all but the first occurrence of that byte.

#### Attack
The idea of the attack for Threat Model 2 is the following:
1. For each possible value in 0..255:
	1. We set every byte of our key to this value and run the code, populating the Reuse Buffer with a single entry.
	2. Victim runs the code with its secret key. We get to know in which iterations CR happened as described above, and we store the trace.
2. We compute the intersection of all the traces. These are positions for which CR always happened, which won't be possible to leak and will be ignored.
3. For each possible value in 0..255, we set the positions of the corresponding trace to the value.

This attack has been implemented [here](../src/attack_auth_cr.py). Note that it requires an attacker to be able to get and analyze the trace of CRs, including the PC in which they happened.