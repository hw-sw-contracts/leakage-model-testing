# sha512-libsodium
## Silent Stores
#### On both initialized and uninitialized memory
| Id | Count |                                                                             Line                                                                            |
|:--:|------:|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1  |   903 | `crypto_hash_sha512_update` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L233          |
| 2  |   258 | `store64_be` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L162                              |
| 3  |   253 | `store64_be` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L164                              |
| 4  |   252 | `store64_be` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L166                              |
| 5  |   239 | `store64_be` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L167                              |
| 6  |   225 | `store64_be` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L161                              |
| 7  |   222 | `store64_be` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L163                              |
| 8  |   217 | `store64_be` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L168                              |
| 9  |   197 | `store64_be` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L165                              |
| 10 |   186 | `__memset_sse2_unaligned_erms` at ??#L?                                                                                                                     |
| 11 |    84 | `be64dec_vect` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L56                        |
| 12 |    18 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L141 (discriminator 2) |

The most seen silent store (entry 1) that causes violations is at `crypto_hash_sha512_update`, when copying the input into `state->buf`. This `buf` is [not initialised](https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L195) in `crypto_hash_sha512_init`, but it is [cleared](https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L266) in `crypto_hash_sha512_finish`. Assuming its content is nullbytes, these silent stores in `state->buf` would leak which bytes of the input are zero.

There are also many silent stores in `store64_be` (entries 2 to 9), which is called from [`be64enc_vec`](https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L41), which is called from [`SHA512_Pad`](https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L190) and [`crypto_hash_sha512_final`](https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L264). In the first case, it is writing `state->count` into `&state->buf[112]`, so the same as before applies. In the second case, it is writing the final `state->state` into the output buffer. Silent stores to the output buffer [has already been discussed](#stream_xor-libsodium).

Finally, the silent stores in `be64dec_vect` (entry 11) are happening when calling `SHA512_Transform` from [here](https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L191). It is reading from `state->buf` and writing it to `tmp64`. But once more, `tmp64` is being [cleared](https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L265) in `crypto_hash_sha512_final`.


#### Just on initialized memory
| Id | Count |                   Line                  |
|:--:|------:|:----------------------------------------|
| 1  |   194 | `__memset_sse2_unaligned_erms` at ??#L? |

Probably not interesting.

## Register File Compression
| Id | Count  |                                                                             Line                                                                            |
|:--:|-------:|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1  | 982062 | `rotr64` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L58 (discriminator 1)                 |
| 2  | 444828 | `rotr64` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L58 (discriminator 2)                 |
| 3  |  31415 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L136 (discriminator 1) |
| 4  |  31413 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L130 (discriminator 1) |
| 5  |  31413 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L134 (discriminator 1) |
| 6  |  31412 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L126 (discriminator 1) |
| 7  |  31412 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L127 (discriminator 1) |
| 8  |  31412 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L129 (discriminator 1) |
| 9  |  31412 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L131 (discriminator 1) |
| 10 |  31412 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L133 (discriminator 1) |
| 11 |  31411 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L128 (discriminator 1) |
| 12 |  31411 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L132 (discriminator 1) |
| 13 |  31410 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L135 (discriminator 1) |
| 14 |  31400 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L125 (discriminator 1) |
| 15 |  25131 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L124 (discriminator 1) |
| 16 |  25130 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L123 (discriminator 1) |
| 17 |  19907 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L143 (discriminator 2) |
| 18 |  18396 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L141 (discriminator 2) |
| 19 |  17801 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L142 (discriminator 2) |
| 20 |  16752 | `store64_be` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L162                              |
| 21 |  16752 | `store64_be` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L163                              |
| 22 |  16752 | `store64_be` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L164                              |
| 23 |  16752 | `store64_be` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L165                              |
| 24 |  16752 | `store64_be` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L166                              |
| 25 |  16740 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L144 (discriminator 2) |
| 26 |  14716 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L146 (discriminator 2) |
| 27 |  14708 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L147 (discriminator 2) |
| 28 |  14706 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L145 (discriminator 2) |
| 29 |  10518 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L148 (discriminator 2) |
| 30 |  10510 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L151 (discriminator 2) |
| 31 |  10470 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L137 (discriminator 1) |
| 32 |   8426 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L154 (discriminator 2) |
| 33 |   8416 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L149 (discriminator 2) |
| 34 |   8416 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L150 (discriminator 2) |
| 35 |   8377 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L122 (discriminator 1) |
| 36 |   8376 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L155 (discriminator 2) |
| 37 |   4238 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L152 (discriminator 2) |
| 38 |     74 | `store64_be` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L167                              |
| 39 |     40 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L153 (discriminator 2) |
| 40 |     36 | `load64_be` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L142                               |
| 41 |     15 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L156 (discriminator 2) |

## Narrow Register File Compression
| Id | Count |                                                                             Line                                                                            |
|:--:|------:|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1  |   243 | `rotr64` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L58 (discriminator 2)                 |
| 2  |   140 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L143 (discriminator 2) |
| 3  |   121 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L142 (discriminator 2) |
| 4  |   109 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L141 (discriminator 2) |
| 5  |   107 | `load64_be` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L142                               |
| 6  |    95 | `store64_be` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L165                              |
| 7  |    18 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L156 (discriminator 2) |
| 8  |    15 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L144 (discriminator 2) |
| 9  |     6 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L148 (discriminator 2) |
| 10 |     5 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L145 (discriminator 2) |
| 11 |     2 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L150 (discriminator 2) |
| 12 |     1 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L122 (discriminator 1) |

## Computation Simplification
| Id | Count |                                                                             Line                                                                            |
|:--:|------:|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1  |    66 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L143 (discriminator 2) |
| 2  |    64 | `rotr64` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L58 (discriminator 2)                 |
| 3  |    41 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L141 (discriminator 2) |
| 4  |    36 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L142 (discriminator 2) |
| 5  |    20 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L156 (discriminator 2) |
| 6  |    13 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L122 (discriminator 1) |
| 7  |     9 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L125 (discriminator 1) |
| 8  |     9 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L144 (discriminator 2) |
| 9  |     7 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L123 (discriminator 1) |
| 10 |     6 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L124 (discriminator 1) |
| 11 |     5 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L148 (discriminator 2) |

## Operand Packing
| Id | Count |                                                                             Line                                                                            |
|:--:|------:|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1  |    49 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L141 (discriminator 2) |
| 2  |    41 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L143 (discriminator 2) |
| 3  |    25 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L142 (discriminator 2) |
| 4  |    15 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L146 (discriminator 2) |
| 5  |    15 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L147 (discriminator 2) |
| 6  |    15 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L148 (discriminator 2) |
| 7  |    15 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L156 (discriminator 2) |
| 8  |    12 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L150 (discriminator 2) |
| 9  |     9 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L145 (discriminator 2) |
| 10 |     9 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L149 (discriminator 2) |
| 11 |     9 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L151 (discriminator 2) |
| 12 |     9 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L152 (discriminator 2) |
| 13 |     9 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L153 (discriminator 2) |
| 14 |     9 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L154 (discriminator 2) |
| 15 |     9 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L155 (discriminator 2) |
| 16 |     6 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L158 (discriminator 3) |
| 17 |     1 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L144 (discriminator 2) |

## Computation Reuse
| Id | Count |                                                                             Line                                                                            |
|:--:|------:|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1  |    15 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L142 (discriminator 2) |
| 2  |    10 | `rotr64` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L58 (discriminator 2)                 |

## Computation Reuse (keeping state of first input)
| Id | Count | Line                                                                                                                                                        |
|:--:|------:|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1  |     6 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L142 (discriminator 2) |
| 2  |     4 | `rotr64` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/common.h#L58 (discriminator 2)                 |
| 3  |     2 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L141 (discriminator 2) |
| 4  |     1 | `SHA512_Transform` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L143 (discriminator 2) |