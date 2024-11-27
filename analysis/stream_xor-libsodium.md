# stream_xor-libsodium
The function `crypto_stream_xor(out, m, mlen, nonce, k)` encrypts a message `m` of length `mlen` using a nonce `nonce`, whose length must be 24, and a key `k`, whose length must be 32. The ciphertext is the message xored with the output of the stream cipher.

## Summary of the operations
1. It computes a `subkey` from the key and the nonce. This is done ciphering the first 16 bytes of the nonce with `crypto_core_hsalsa20` using the key.
2. The ciphering of the message is done in blocks of 64 bytes. For each block, it computes the corresponding cipher block and xors the message with it, producing the ciphertext. To compute the cipher block:
	1. The number of the block (0, 1, ...) is encoded in little endian and appended to the last 8 bytes of the nonce.
	2. The resulting 16 bytes are ciphered with `crypto_core_salsa20` using the subkey, producing the cipher block.

More details can be seen [here](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)).

## Silent Stores
#### On both initialized and uninitialized memory
| Id | Count |                                                                         Line                                                                         |
|:--:|------:|:-----------------------------------------------------------------------------------------------------------------------------------------------------|
| 1  |  1566 | `stream_ref_xor_ic` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_stream/salsa20/ref/salsa20_ref.c#L105          |
| 2  |    86 | `crypto_core_hsalsa20` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/hsalsa20/ref2/core_hsalsa20_ref2.c#L27 |
| 3  |    44 | `crypto_core_hsalsa20` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/hsalsa20/ref2/core_hsalsa20_ref2.c#L39 |

We can see most violations happen at the operation `c[i] = m[i] ^ block[i]`. Since `c` is the output buffer given by the user, we are marking it as "uninitialized". If `c` is initialized to zero, silent stores happen when the message matches the block used to cipher, leaking the block. If in place encryption is used, silent stores happen when the block byte is zero, leaking which bytes of the ciphertext are unchanged with respect to the plaintext.

The other two places at `crypto_core_hsalsa20` are very similar to the ones at `crypto_core_salsa20` analysed before: it looks like the first 12 bytes of the key are being spilled into the stack, and are not cleared at the end of the function. However, after `crypto_core_hsalsa20` there are more functions that reuse the same stack region, overwriting those values. In particular, `block` in `stream_ref_xor_ic` is placed there, and it [is being cleared](https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_stream/salsa20/ref/salsa20_ref.c#L108) afterwards. Therefore, these silent stores happen when part of the key is zero, which is not interesting.

The silent stores that happen at `crypto_core_salsa20` in [salsa-libsodium](salsa-libsodium.md#silent-stores) can also happen here. But now, what is being spilled to the stack is the subkey. Silent stores would tell us how many bytes of the subkey match the subkey of the previous execution. However, since changing a single bit in the key produces a totally different key, it isn't feasible for an attacker to leak the key this way. It is only possible to check if a given key is the same as the previous one, since both would produce the same subkey.

#### Just on initialized memory
| Id | Count |    PC    | Line                                                                                                                                                                   |
|:--:|------:|:--------:|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1  |     1 | 0x4027bf | `crypto_core_hsalsa20` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/hsalsa20/ref2/core_hsalsa20_ref2.c#L67 (discriminator 3) |
This is another instance of stack spilling. The variable `x1` is stored in the stack. When the result of `(x0 + x3) >> 7` equals 0, the same value `x1` is written into the stack, resulting in a silent store. However, this is quite unlikely and I don't think it's exploitable.


## Computation Simplification
| Id | Count |                                                                                  Line                                                                                  |
|:--:|------:|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1  |   437 | `stream_ref_xor_ic` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_stream/salsa20/ref/salsa20_ref.c#L105                            |
| 2  |    20 | `crypto_core_hsalsa20` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/hsalsa20/ref2/core_hsalsa20_ref2.c#L56 (discriminator 3) |
| 3  |    20 | `crypto_core_hsalsa20` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/hsalsa20/ref2/core_hsalsa20_ref2.c#L59 (discriminator 3) |
| 4  |    19 | `crypto_core_hsalsa20` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/hsalsa20/ref2/core_hsalsa20_ref2.c#L63 (discriminator 3) |
| 5  |    19 | `crypto_core_hsalsa20` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/hsalsa20/ref2/core_hsalsa20_ref2.c#L57 (discriminator 3) |
| 6  |    19 | `crypto_core_hsalsa20` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/hsalsa20/ref2/core_hsalsa20_ref2.c#L60 (discriminator 3) |
| 7  |    18 | `crypto_core_hsalsa20` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/hsalsa20/ref2/core_hsalsa20_ref2.c#L53 (discriminator 3) |
| 8  |    16 | `crypto_core_hsalsa20` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/hsalsa20/ref2/core_hsalsa20_ref2.c#L65 (discriminator 3) |
| 9  |    16 | `crypto_core_hsalsa20` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/hsalsa20/ref2/core_hsalsa20_ref2.c#L51 (discriminator 3) |


## Operand Packing
| Id | Count |                                                                    Line                                                                   |
|:--:|------:|:------------------------------------------------------------------------------------------------------------------------------------------|
| 1  |     1 | `crypto_core_salsa` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/salsa/ref/core_salsa_ref.c#L88 |

## Computation Reuse
| Id | Count |                                                                     Line                                                                    |
|:--:|------:|:--------------------------------------------------------------------------------------------------------------------------------------------|
| 1  |  1280 | `stream_ref_xor_ic` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_stream/salsa20/ref/salsa20_ref.c#L105 |

A CR in `m[i] ^ block[i]` would mean that there's a pair `(m[i], block[i])` whose XOR has been computed before. Setting `m` to a constant byte would allow an attacker to leak how many bytes of the block are repeated, which is not very interesting.

## Computation Reuse (keeping state of first input)
| Id | Count | Line                                                                                                                                        |
|:--:|------:|:--------------------------------------------------------------------------------------------------------------------------------------------|
| 1  |   259 | `stream_ref_xor_ic` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_stream/salsa20/ref/salsa20_ref.c#L105 |
