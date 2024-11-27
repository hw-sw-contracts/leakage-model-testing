# x25519-libsodium
## Silent Stores
#### On both initialized and uninitialized memory
| Id | Count | Line                                                                                                                                                                                 |
|:--:|------:|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1  |  9604 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L174                                       |
| 2  |  9604 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L175                                       |
| 3  |  9604 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L176                                       |
| 4  |  9604 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L177                                       |
| 5  |  9604 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L178                                       |
| 6  |  9604 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L180                                       |
| 7  |  9604 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L181                                       |
| 8  |  9604 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L182                                       |
| 9  |  9604 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L183                                       |
| 10 |  9604 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L184                                       |
| 11 |  9100 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L244                                         |
| 12 |  8372 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L335                                          |
| 13 |  4802 | `crypto_scalarmult_curve25519_ref10` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c#L108               |
| 14 |  1456 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L147                                       |
| 15 |   364 | `fe25519_sub` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L54                                          |
| 16 |    46 | `crypto_scalarmult_curve25519` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_scalarmult/curve25519/scalarmult_curve25519.c#L25 (discriminator 3) |
| 17 |    17 | `crypto_scalarmult_curve25519_ref10` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c#L98                |
| 18 |    11 | `crypto_scalarmult_curve25519_ref10` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c#L96                |
| 19 |    11 | `crypto_scalarmult_curve25519_ref10` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c#L94                |

#### Just on initialized memory
| Id | Count | Line                                                                                                                                                                                 |
|:--:|------:|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1  |  2584 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L174                                       |
| 2  |  2584 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L177                                       |
| 3  |  2584 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L180                                       |
| 4  |  2584 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L183                                       |
| 5  |  2583 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L175                                       |
| 6  |  2583 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L178                                       |
| 7  |  2583 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L181                                       |
| 8  |  2583 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L184                                       |
| 9  |  2582 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L176                                       |
| 10 |  2582 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L182                                       |
| 11 |  1292 | `crypto_scalarmult_curve25519_ref10` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c#L108               |
| 12 |   850 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L244                                         |
| 13 |   782 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L335                                          |
| 14 |   136 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L147                                       |
| 15 |    34 | `fe25519_sub` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L54                                          |
| 16 |    17 | `crypto_scalarmult_curve25519` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_scalarmult/curve25519/scalarmult_curve25519.c#L25 (discriminator 3) |
| 17 |     6 | `crypto_scalarmult_curve25519_ref10` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c#L98                |
| 18 |     4 | `fe25519_add` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L45                                          |
| 19 |     3 | `fe25519_sub` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L85                                          |
| 20 |     3 | `fe25519_add` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L42                                          |
| 21 |     2 | `crypto_scalarmult_curve25519_ref10` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c#L96                |
| 22 |     2 | `fe25519_add` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L44                                          |
| 23 |     2 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L311                                         |
| 24 |     1 | `fe25519_sub` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L75                                          |
| 25 |     1 | `fe25519_add` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L35                                          |
| 26 |     1 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L267                                         |
| 27 |     1 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L260                                         |
| 28 |     1 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L319                                         |
| 29 |     1 | `fe25519_scalar_product` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L516                              |
| 30 |     1 | `fe25519_scalar_product` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L517                              |
| 31 |     1 | `fe25519_add` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L43                                          |
| 32 |     1 | `crypto_scalarmult_curve25519_ref10` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c#L110               |

#### Analysis
Most silent stores are in `fe25519_cswap`. `cswap` stands for conditional swap. Depending on whether the third argument is 0 or 1, it swaps its two first arguments or writes the same values to each of them. This means we will always see silent stores when the third argument is 0: the swap is not performed, and the same values are written to memory.

The function `fe25519_cswap` is called from [here](https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c#L110). `crypto_scalarmult_curve25519_ref10` is in charge of computing the shared secret, and gets as arguments the output buffer, the secret key, and the public key. First, the secret key is copied to the output buffer. This produces violations when tracking silent stores on uninitialized memory (last entry of the first table), because silent stores happen when a byte of the key matches the value that was previously there. The output buffer is [not cleared](https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_box/curve25519xsalsa20poly1305/box_curve25519xsalsa20poly1305.c#L40) afterwards, in contrast to many other places in the same file (look for calls to `sodium_memzero`). This means that the contents of the output buffer is the shared secret of a previous run. This leaks whether a byte of the secret key matches a byte of the shared secret. In the scenario of an attacker and a service performing key exchange, it potentially leaks the secret key to the attacker, because he knows the shared secret. However, this has not been further explored.

Following with `crypto_scalarmult_curve25519_ref10`, some bits of the secret key [are fixed](https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c#L96): it sets bits 0, 1, 2 and 255 to 0, and bit 254 to 1. Then, the loop iterates every bit of the key, from position 254 to 0. This is where `fe25519_cswap` is called from. The swap is performed depending on the bit of the secret key, effectively leaking that bit to an attacker who is able to measure silent stores. Furthermore, since the swap only depends on the secret key, a single trace with an arbitrary public key is enough to recover the full secret key.


#### Attack details
Actually, the swap is performed according to the variable `swap`. This variable holds the xor of the two last bits of the secret key. Given a trace, we can know if swap happened on every iteration depending on if silent stores in `fec25519_cswap` happened or not. Then, we can leak every bit of the key applying the formula:

$$
\begin{align}
&swap_0 = bit_0 \\\\
&swap_i = bit_i \oplus bit_{i-1}, \quad i > 0
\end{align}
$$

There's another problem though: the trace indicates the silent stores in `fec25519_cswap`, but we don't know in which iterations they took place. In order to solve this, we'll take advantage of a silent store that happens every iteration and use this as a counter. This silent store happens at the beginning of `fec25519_swap` in some `push r13` instruction. Since that function is called twice in a row, the second one seems to produce a silent store when writing `r13` into memory. When analyzing the trace, we can use that silent store to keep track of which iteration the swap occurs on.

The proposed threat model is a service performing key exchange with the attacker. The service secret key and the attacker public key are used to compute the shared secret key. The attacker is able to leak the service secret key by measuring silent stores in `fec25519_swap`. This has been implemented [here](../src/attack_x25519_ssi.py).

Actually, since the attacker keys are not used in the attack at all, the threat model could be simply an attacker being able to measure silent stores while the service performs key exchange with any other client.


## Register File Compression
|  Id | Count | Line                                                                                                                                                                   |
|:---:|------:|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|  1  |  1164 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L168                         |
|  2  |  1164 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L169                         |
|  3  |  1164 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L170                         |
|  4  |  1164 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L171                         |
|  5  |  1160 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L174                         |
|  6  |  1160 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L175                         |
|  7  |  1160 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L176                         |
|  8  |  1160 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L177                         |
|  9  |  1160 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L178                         |
|  10 |   620 | `fe25519_sub` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L64                            |
|  11 |   338 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L380                            |
|  12 |   252 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L386                            |
|  13 |   192 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L307                           |
|  14 |   121 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L299                           |
|  15 |    96 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L360                            |
|  16 |    80 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L273                           |
|  17 |    80 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L300                           |
|  18 |    72 | `fe25519_sub` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L67                            |
|  19 |    64 | `fe25519_sub` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L69                            |
|  20 |    64 | `fe25519_sub` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L72                            |
|  21 |    64 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L379                            |
|  22 |    44 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L308                           |
|  23 |    42 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L311                           |
|  24 |    40 | `fe25519_sub` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L66                            |
|  25 |    40 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L244                           |
|  26 |    40 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L269                           |
|  27 |    40 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L270                           |
|  28 |    40 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L272                           |
|  29 |    40 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L276                           |
|  30 |    40 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L283                           |
|  31 |    40 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L285                           |
|  32 |    40 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L287                           |
|  33 |    40 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L290                           |
|  34 |    40 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L291                           |
|  35 |    40 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L293                           |
|  36 |    40 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L294                           |
|  37 |    40 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L302                           |
|  38 |    40 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L305                           |
|  39 |    40 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L310                           |
|  40 |    40 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L314                           |
|  41 |    40 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L318                           |
|  42 |    40 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L319                           |
|  43 |    35 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L378                            |
|  44 |    34 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L387                            |
|  45 |    33 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L390                            |
|  46 |    33 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L397                            |
|  47 |    32 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L147                         |
|  48 |    32 | `fe25519_sub` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L68                            |
|  49 |    32 | `fe25519_sub` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L70                            |
|  50 |    32 | `fe25519_sub` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L71                            |
|  51 |    32 | `fe25519_sub` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L73                            |
|  52 |    32 | `fe25519_sub` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L65                            |
|  53 |    32 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L335                            |
|  54 |    32 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L359                            |
|  55 |    32 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L358                            |
|  56 |    32 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L362                            |
|  57 |    32 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L363                            |
|  58 |    32 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L364                            |
|  59 |    32 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L368                            |
|  60 |    32 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L366                            |
|  61 |    32 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L367                            |
|  62 |    32 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L370                            |
|  63 |    32 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L374                            |
|  64 |    32 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L376                            |
|  65 |    32 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L381                            |
|  66 |    32 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L384                            |
|  67 |    32 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L389                            |
|  68 |    32 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L393                            |
|  69 |    32 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L398                            |
|  70 |    24 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L185                         |
|  71 |    24 | `crypto_scalarmult_curve25519_ref10` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c#L113 |
|  72 |    24 | `crypto_scalarmult_curve25519_ref10` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c#L114 |
|  73 |    24 | `crypto_scalarmult_curve25519_ref10` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c#L117 |
|  74 |    24 | `crypto_scalarmult_curve25519_ref10` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c#L118 |
|  75 |    24 | `crypto_scalarmult_curve25519_ref10` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c#L122 |
|  76 |    24 | `crypto_scalarmult_curve25519_ref10` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c#L123 |
|  77 |    24 | `crypto_scalarmult_curve25519_ref10` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c#L124 |
|  78 |    24 | `crypto_scalarmult_curve25519_ref10` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c#L130 |
|  79 |    16 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L172                         |
|  80 |    16 | `crypto_scalarmult_curve25519_ref10` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c#L111 |
|  81 |    16 | `fe25519_sub` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L86                            |
|  82 |    16 | `crypto_scalarmult_curve25519_ref10` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c#L119 |
|  83 |    16 | `crypto_scalarmult_curve25519_ref10` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c#L120 |
|  84 |    16 | `crypto_scalarmult_curve25519_ref10` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c#L125 |
|  85 |    16 | `fe25519_scalar_product` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L502                |
|  86 |    16 | `crypto_scalarmult_curve25519_ref10` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c#L127 |
|  87 |    16 | `crypto_scalarmult_curve25519_ref10` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c#L129 |
|  88 |    16 | `crypto_scalarmult_curve25519_ref10` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c#L110 |
|  89 |     9 | `fe25519_scalar_product` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L507                |
|  90 |     9 | `fe25519_scalar_product` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L509                |
|  91 |     8 | `fe25519_add` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L44                            |
|  92 |     8 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L405                            |
|  93 |     8 | `fe25519_scalar_product` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L501                |
|  94 |     8 | `fe25519_scalar_product` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L503                |
|  95 |     8 | `fe25519_scalar_product` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L504                |
|  96 |     8 | `fe25519_scalar_product` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L505                |
|  97 |     8 | `fe25519_scalar_product` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L506                |
|  98 |     8 | `fe25519_scalar_product` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L508                |
|  99 |     1 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L394                            |
| 100 |     1 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L395                            |
| 101 |     1 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L343                            |

#### Analysis
When the third argument of `fe25519_cswap` is 0, `mask` is also 0. Then, when performing `x0 = x0 & mask` the result is also 0, and RFC triggers. This allows an attacker with the trace of RFC to leak the value of `swap` in the [main function](https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c#L110), leaking the secret key. Since we only care about that RFC, which always happen on 0, we can use both the leakage model that keeps track of every RFC and the one that triggers only on 0.

Similarly to other attacks, we need something to know which iteration the observations belong to. We can use some RFC that happens every iteration. Taking a look at the traces, I found RFC always triggers [here](https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/include/sodium/private/ed25519_ref10_fe_51.h#L504), when performing `a >> 51`. `a` is of type `uint128_t`, and it's the result of a product between a 64 and a 32 bit integers, and an addition with a 64 bit integer. This means its maximum value is `MAX_UINT64 * MAX_UINT32 + MAX_UINT32`, which takes 96 bits. `a` is stored in registers `rdi:rsi` (`rdi` for the upper 64 bits and `rsi` for the lower one). In order to compute `a >> 51`, one of the steps is doing `rdi >> 51`, which shifts the upper 64 bits. As `a` can take up to 96 bits, its upper 64 bits can take up to 96-64=32 bits. This means that shifting its upper 64 bits by 51 will always yield 0, producing RFC.

Measuring the RFC that happens once every iteration we can keep track of which iteration we are in. Then, if we measure the `x0 & mask` RFC on 0, this means `swap = 0`. Otherwise, `swap = 1`. The same threat model as in [silent stores](#attack-details) has been implemented and exploited [here](../src/attack_x25519_rfc0.py) for RFC on 0, and [here](../src/attack_x25519_rfc.py) for RFC on every value.

## Narrow Register File Compression
| Id | Count | Line                                                                                                                                                    |
|:--:|------:|:--------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1  |   652 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L148          |
| 2  |   652 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L168          |
| 3  |   652 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L169          |
| 4  |   652 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L170          |
| 5  |   652 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L171          |
| 6  |   652 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L172          |
| 7  |   144 | `fe25519_sub` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L72             |
| 8  |   120 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L300            |
| 9  |    60 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L303            |
| 10 |    60 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L306            |
| 11 |    60 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L309            |
| 12 |    60 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L314            |
| 13 |    60 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L317            |
| 14 |    48 | `fe25519_sub` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L64             |
| 15 |    48 | `fe25519_sub` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L66             |
| 16 |    48 | `fe25519_sub` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L68             |
| 17 |    48 | `fe25519_sub` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L70             |
| 18 |    48 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L379             |
| 19 |    48 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L382             |
| 20 |    48 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L385             |
| 21 |    48 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L388             |
| 22 |    48 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L393             |
| 23 |    48 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L396             |
| 24 |    48 | `fe25519_scalar_product` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L502 |
| 25 |    36 | `fe25519_scalar_product` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L504 |
| 26 |    36 | `fe25519_scalar_product` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L506 |
| 27 |    24 | `fe25519_scalar_product` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L508 |

#### Analysis
The same attack as in [register file compression](#analysis-1) also applies here. The attack script is exactly the same, with a small difference.
In the first iteration `swap` is 1, because that bit is fixed to be 1. So [here](https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/include/sodium/private/ed25519_ref10_fe_51.h#L168) `mask` has all its bits set to 1. The problem is that `x0` is 1 in that iteration, so the result of the AND operation is 1, and NRFC triggers. The script expects NRFC to trigger only when `swap` is 0, because the reuslt of the AND operation would be 0. Therefore, we have to ignore the first iteration, and fix that bit to 1. Note that this issue also happens if `x0` is a narrow value in any of the next iterations, but this is quite unlikely.

You can see the attack script [here](../src/attack_x25519_nrfc.py).

## Computation Simplification
| Id | Count | Line                                                                                                                                                                                 |
|:--:|------:|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1  |   796 | `fe25519_cswap` at https://github.com/jedisct1a/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L180                                       |
| 2  |   796 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L181                                       |
| 3  |   796 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L182                                       |
| 4  |   796 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L183                                       |
| 5  |   796 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L184                                       |
| 6  |   796 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L174                                       |
| 7  |   796 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L175                                       |
| 8  |   796 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L176                                       |
| 9  |   796 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L177                                       |
| 10 |   796 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L178                                       |
| 11 |   521 | `crypto_scalarmult_curve25519_ref10` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c#L108               |
| 12 |   463 | `crypto_scalarmult_curve25519_ref10` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c#L109               |
| 13 |   312 | `crypto_scalarmult_curve25519_ref10` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c#L107               |
| 14 |   110 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L319                                         |
| 15 |    88 | `fe25519_sub` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L64                                          |
| 16 |    88 | `fe25519_sub` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L66                                          |
| 17 |    88 | `fe25519_sub` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L68                                          |
| 18 |    88 | `fe25519_sub` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L70                                          |
| 19 |    88 | `fe25519_sub` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L75                                          |
| 20 |    88 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L398                                          |
| 21 |    44 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L172                                       |
| 22 |    44 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L168                                       |
| 23 |    44 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L169                                       |
| 24 |    44 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L170                                       |
| 25 |    44 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L171                                       |
| 26 |     3 | `crypto_scalarmult_curve25519` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_scalarmult/curve25519/scalarmult_curve25519.c#L25 (discriminator 3) |

#### Analysis
There are many violations in `fe25519_cswap`. First 10 entries correspond to the [xor operations](https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L174) at the end of the function. The other 5 entries, from 21 to 25, correspond to the [and operations with the computed mask](https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L172).

When the third argument of `fe25519_cswap` is 0, `mask` is also 0. Then, the operations `x = x & mask` produce a trivial computation simplification (CS). The result is `x = 0`. Finally, computing `f ^ x` and `g ^ x` produce a semi-trivial CS.

When the third argument of `fe25519_cswap` is 1, `mask` is `0xFFFFFFFFFFFFFFFF` (64 bits set to 1). Then, the operations `x = x & mask` produce a semi-trivial CS, leaving `x` unchanged. Finally, computing `f ^ x` and `g ^ x` doesn't produce any CS.

This means that an attacker with the trace of CS can leak the value of `swap` in the [main function](https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c#L110). `fe25519_cswap` is called twice every iteration. If `swap` is 0, there will be two CS in each call, and therefore four in that iteration. Otherwise, if `swap` is 1, there will be a single CS in each call, and therefore two in that iteration. As `swap` depends on each bit of the secret key, leaking it leads to leaking the secret key.

Note that this would not be exploitable (or not as easily) if we were tracking only trivial CS, and not semi-trivial. We would only produce observations in iterations where `swap = 0`. This means we wouldn't know which iteration those observations belong to, because there doesn't seem to be anything that we can use as separator.

Similarly to the attack for [silent stores](#attack-details) and with the same threat model, this has been implemented [here](../src/attack_x25519_cs.py).



## Narrow Computation Simplification
| Id | Count | Line                                                                                                                                         |
|:--:|------:|:---------------------------------------------------------------------------------------------------------------------------------------------|
| 1  |    79 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L367  |
| 2  |    69 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L358  |
| 3  |    59 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L269 |
| 4  |    50 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L376  |
| 5  |    50 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L291 |
| 6  |    44 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L372  |
| 7  |    41 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L362  |
| 8  |    40 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L295 |
| 9  |    38 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L278 |
| 10 |    36 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L277 |
| 11 |    36 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L364  |
| 12 |    36 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L275 |
| 13 |    34 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L285 |
| 14 |    33 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L276 |
| 15 |    33 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L293 |
| 16 |    32 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L282 |
| 17 |    30 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L284 |
| 18 |    28 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L279 |
| 19 |    26 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L374  |
| 20 |    26 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L297 |
| 21 |    24 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L370  |
| 22 |    22 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L270 |
| 23 |    21 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L368  |
| 24 |    21 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L375  |
| 25 |    20 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L287 |
| 26 |    19 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L271 |
| 27 |    19 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L296 |
| 28 |    19 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L290 |
| 29 |    18 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L273 |
| 30 |    18 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L294 |
| 31 |    18 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L363  |
| 32 |    17 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L272 |
| 33 |    16 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L366  |
| 34 |    16 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L281 |
| 35 |    15 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L360  |
| 36 |    15 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L283 |
| 37 |    14 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L359  |
| 38 |    14 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L289 |
| 39 |    13 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L288 |
| 40 |     9 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L371  |

[This paper](https://infoscience.epfl.ch/record/223794) targets a 32-bit implementation. Field elements are represented by 10 32-bit integers. The problem they found is that 64-bit integer multiplication is handled by a library function. This function checked if both integers were actually less than 32-bit, and in that case it performed a faster computation. This broke the constant time implementation. They target `fscalar_product`, which is in charge of multiplying a field element `in` by a constant `scalar`. There's a loop like this, in which the multiplication is handled by the library function:
```c
for (i = 0; i < 10; i++) {
	output[i] = in[i] ∗ scalar;
}
```
The analogous function in libsodium is `fe25519_scalar_product`. Since the optimization performed by the multiplication function is very similar to what we have implemented for this leakage model, we expected to see violations there. The loop is also present [here](https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/include/sodium/private/ed25519_ref10_fe_25_5.h#L995), but unrolled. There, coefficients are sign-extended into 64 bits. This means the upper 32 bits will be 0 for positive coefficientes, and 1 for negative coefficientes. Then, they are multiplied by the scalar. When called from [the main function](https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c#L126), `scalar` is 121666, which is positive. This means we should produce an observation for every positive coefficient, because it would be a multiplication of two narrow 64-bit integers.

The reason we are not seeing any violation in `fe25519_scalar_product` is because libsodium defaults to another implementation when building for 64 bits. Instead of using 10 32-bit integers for representing field elements, it uses 5 64-bit integers, as you can see [here](https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/include/sodium/private/ed25519_ref10.h#L13). The implementation of `fe25519_scalar_product` [also changes](https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/include/sodium/private/ed25519_ref10_fe_51.h#L493). Now there are no sign-extensions, so computation simplification happens simply when a coefficient has its upper bits set to 0, which is unlikely.

We can build libsodium with `CFLAGS="-UHAVE_TI_MODE -g -O2" ./configure --disable-asm` to make it use the other implementation. When fuzzing this implementation, we find violations in `fe25519_sq` and `fe25519_mul` as we do here. But we also find violations in [every multiplication](https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/include/sodium/private/ed25519_ref10_fe_25_5.h#L995) of `fe25519_scalar_product`, as expected. This means the attack used in the paper (which I don't understand) should also apply here. But now, the leak is due to a (simulated) hardware optimization instead of a software optimization.

## Operand Packing
|  Id | Count | Line                                                                                                                                                                                                   |
|:---:|------:|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|  1  |   510 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L148                                                         |
|  2  |   510 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L271                                                           |
|  3  |   509 | `fe25519_scalar_product` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L502                                                |
|  4  |   509 | `fe25519_scalar_product` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L504                                                |
|  5  |   509 | `fe25519_scalar_product` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L506                                                |
|  6  |   509 | `fe25519_scalar_product` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L508                                                |
|  7  |   263 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L294                                                           |
|  8  |   259 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L295                                                           |
|  9  |   258 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L282                                                           |
|  10 |   257 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L289                                                           |
|  11 |   255 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L288                                                           |
|  12 |   254 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L276                                                           |
|  13 |   254 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L277                                                           |
|  14 |   254 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L283                                                           |
|  15 |   254 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L300                                                           |
|  16 |   254 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L303                                                           |
|  17 |   254 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L306                                                           |
|  18 |   254 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L309                                                           |
|  19 |   254 | `crypto_scalarmult_curve25519_ref10` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c#L106                                 |
|  20 |   253 | `crypto_scalarmult_curve25519_ref10` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c#L109                                 |
|  21 |   253 | `crypto_scalarmult_curve25519_ref10` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c#L107                                 |
|  22 |   253 | `crypto_scalarmult_curve25519_ref10` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c#L108                                 |
|  23 |   100 | `fe25519_invert` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c#L95 (discriminator 3)                                            |
|  24 |    48 | `fe25519_invert` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c#L90 (discriminator 3)                                            |
|  25 |    48 | `fe25519_invert` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c#L100 (discriminator 3)                                           |
|  26 |    18 | `fe25519_invert` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c#L80 (discriminator 3)                                            |
|  27 |    10 | `fe25519_invert` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c#L75 (discriminator 3)                                            |
|  28 |    10 | `fe25519_invert` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c#L85 (discriminator 3)                                            |
|  29 |    10 | `crypto_core_hsalsa20` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/hsalsa20/ref2/core_hsalsa20_ref2.c#L50 (discriminator 3)                                 |
|  30 |     6 | `fe25519_sub` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L66                                                            |
|  31 |     6 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L375                                                            |
|  32 |     5 | `fe25519_sub` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L70                                                            |
|  33 |     5 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L174                                                         |
|  34 |     5 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L297                                                           |
|  35 |     4 | `fe25519_sub` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L72                                                            |
|  36 |     4 | `fe25519_invert` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c#L70 (discriminator 3)                                            |
|  37 |     4 | `fe25519_invert` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c#L105 (discriminator 3)                                           |
|  38 |     4 | `fe25519_reduce` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/ed25519/ref10/fe_51/fe.h#L44                                                                   |
|  39 |     4 | `fe25519_reduce` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/ed25519/ref10/fe_51/fe.h#L55                                                                   |
|  40 |     4 | `fe25519_reduce` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/ed25519/ref10/fe_51/fe.h#L71                                                                   |
|  41 |     3 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L180                                                         |
|  42 |     3 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L175                                                         |
|  43 |     3 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L367                                                            |
|  44 |     3 | `fe25519_add` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L36                                                            |
|  45 |     3 | `fe25519_sub` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L64                                                            |
|  46 |     3 | `fe25519_sub` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L68                                                            |
|  47 |     3 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L291                                                           |
|  48 |     2 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L172                                                         |
|  49 |     2 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L183                                                         |
|  50 |     2 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L184                                                         |
|  51 |     2 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L178                                                         |
|  52 |     2 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L181                                                         |
|  53 |     2 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L383                                                            |
|  54 |     2 | `fe25519_add` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L35                                                            |
|  55 |     2 | `fe25519_reduce` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/ed25519/ref10/fe_51/fe.h#L36                                                                   |
|  56 |     2 | `fe25519_reduce` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/ed25519/ref10/fe_51/fe.h#L38                                                                   |
|  57 |     2 | `fe25519_reduce` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/ed25519/ref10/fe_51/fe.h#L40                                                                   |
|  58 |     2 | `fe25519_reduce` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/ed25519/ref10/fe_51/fe.h#L42                                                                   |
|  59 |     2 | `fe25519_reduce` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/ed25519/ref10/fe_51/fe.h#L47                                                                   |
|  60 |     2 | `fe25519_reduce` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/ed25519/ref10/fe_51/fe.h#L49                                                                   |
|  61 |     2 | `fe25519_reduce` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/ed25519/ref10/fe_51/fe.h#L51                                                                   |
|  62 |     2 | `fe25519_reduce` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/ed25519/ref10/fe_51/fe.h#L53                                                                   |
|  63 |     2 | `fe25519_reduce` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/ed25519/ref10/fe_51/fe.h#L63                                                                   |
|  64 |     2 | `fe25519_reduce` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/ed25519/ref10/fe_51/fe.h#L67                                                                   |
|  65 |     2 | `fe25519_reduce` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/ed25519/ref10/fe_51/fe.h#L65                                                                   |
|  66 |     2 | `fe25519_reduce` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/ed25519/ref10/fe_51/fe.h#L69                                                                   |
|  67 |     2 | `fe25519_reduce` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/ed25519/ref10/fe_51/fe.h#L84                                                                   |
|  68 |     2 | `fe25519_reduce` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/ed25519/ref10/fe_51/fe.h#L86                                                                   |
|  69 |     2 | `fe25519_reduce` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/ed25519/ref10/fe_51/fe.h#L88                                                                   |
|  70 |     2 | `crypto_scalarmult_curve25519` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_scalarmult/curve25519/scalarmult_curve25519.c#L27                                     |
|  71 |     2 | `crypto_box_curve25519xsalsa20poly1305_beforenm` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_box/curve25519xsalsa20poly1305/box_curve25519xsalsa20poly1305.c#L46 |
|  72 |     2 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L171                                                         |
|  73 |     2 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L162                                                         |
|  74 |     2 | `fe25519_add` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L39                                                            |
|  75 |     2 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L310                                                           |
|  76 |     2 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L360                                                            |
|  77 |     2 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L371                                                            |
|  78 |     2 | `fe25519_add` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L45                                                            |
|  79 |     1 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L398                                                            |
|  80 |     1 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L363                                                            |
|  81 |     1 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L366                                                            |
|  82 |     1 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L380                                                            |
|  83 |     1 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L382                                                            |
|  84 |     1 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L284                                                           |
|  85 |     1 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L304                                                           |
|  86 |     1 | `fe25519_add` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L43                                                            |
|  87 |     1 | `fe25519_reduce` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/ed25519/ref10/fe_51/fe.h#L34                                                                   |
|  88 |     1 | `fe25519_reduce` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/ed25519/ref10/fe_51/fe.h#L39                                                                   |
|  89 |     1 | `fe25519_reduce` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/ed25519/ref10/fe_51/fe.h#L41                                                                   |
|  90 |     1 | `fe25519_reduce` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/ed25519/ref10/fe_51/fe.h#L43                                                                   |
|  91 |     1 | `fe25519_reduce` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/ed25519/ref10/fe_51/fe.h#L45                                                                   |
|  92 |     1 | `fe25519_reduce` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/ed25519/ref10/fe_51/fe.h#L48                                                                   |
|  93 |     1 | `fe25519_reduce` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/ed25519/ref10/fe_51/fe.h#L50                                                                   |
|  94 |     1 | `fe25519_reduce` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/ed25519/ref10/fe_51/fe.h#L54                                                                   |
|  95 |     1 | `fe25519_reduce` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/ed25519/ref10/fe_51/fe.h#L52                                                                   |
|  96 |     1 | `fe25519_reduce` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/ed25519/ref10/fe_51/fe.h#L64                                                                   |
|  97 |     1 | `fe25519_reduce` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/ed25519/ref10/fe_51/fe.h#L56                                                                   |
|  98 |     1 | `fe25519_reduce` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/ed25519/ref10/fe_51/fe.h#L76                                                                   |
|  99 |     1 | `fe25519_reduce` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/ed25519/ref10/fe_51/fe.h#L66                                                                   |
| 100 |     1 | `fe25519_reduce` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/ed25519/ref10/fe_51/fe.h#L77                                                                   |
| 101 |     1 | `fe25519_reduce` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/ed25519/ref10/fe_51/fe.h#L68                                                                   |
| 102 |     1 | `fe25519_reduce` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/ed25519/ref10/fe_51/fe.h#L70                                                                   |
| 103 |     1 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L169                                                         |
| 104 |     1 | `fe25519_add` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L42                                                            |
| 105 |     1 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L290                                                           |
| 106 |     1 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L163                                                         |
| 107 |     1 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L177                                                         |
| 108 |     1 | `fe25519_add` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L38                                                            |
| 109 |     1 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L182                                                         |
| 110 |     1 | `fe25519_add` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L37                                                            |
| 111 |     1 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L351                                                            |
| 112 |     1 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L273                                                           |
| 113 |     1 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L313                                                           |
| 114 |     1 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L314                                                           |
| 115 |     1 | `fe25519_add` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L44                                                            |
| 116 |     1 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L386                                                            |
| 117 |     1 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L388                                                            |
| 118 |     1 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L389                                                            |

The first entry corresponds to violations in the `neg` instruction of `fe25519_cswap` [here](https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/include/sodium/private/ed25519_ref10_fe_51.h#L148). Since it is called twice per iteration, the `neg` of the second call is being packed with the `neg` of the first call. The operand is always 0 or 1, so it's always narrow. I believe this operand packing doesn't depend on the secret key. In fact, it should always happen exactly 256 times, one per bit of the key. But there are two violations where in one of the traces the OP at the `neg` instruction triggers one and zero times respectively. I'm not sure why, it may be a bug.



## Computation Reuse
| Id | Count | Line                                                                                                                                                                                 |
|:--:|------:|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1  |   604 | `fe25519_scalar_product` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L504                              |
| 2  |   595 | `fe25519_scalar_product` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L502                              |
| 3  |   566 | `fe25519_scalar_product` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L506                              |
| 4  |   549 | `fe25519_scalar_product` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L508                              |
| 5  |    93 | `crypto_scalarmult_curve25519_ref10` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c#L108               |
| 6  |    10 | `crypto_scalarmult_curve25519_ref10` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c#L109               |
| 7  |     6 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L148                                       |
| 8  |     6 | `fe25519_sub` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L73                                          |
| 9  |     4 | `fe25519_sub` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L70                                          |
| 10 |     4 | `fe25519_sub` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L79                                          |
| 11 |     4 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L372                                          |
| 12 |     4 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L360                                          |
| 13 |     3 | `fe25519_sub` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L68                                          |
| 14 |     3 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L271                                         |
| 15 |     3 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L363                                          |
| 16 |     2 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L184                                       |
| 17 |     2 | `fe25519_sub` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L71                                          |
| 18 |     2 | `fe25519_sub` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L72                                          |
| 19 |     2 | `fe25519_sub` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L76                                          |
| 20 |     2 | `fe25519_sub` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L75                                          |
| 21 |     2 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L279                                         |
| 22 |     2 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L294                                         |
| 23 |     2 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L295                                         |
| 24 |     2 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L398                                          |
| 25 |     2 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L371                                          |
| 26 |     2 | `fe25519_sub` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L77                                          |
| 27 |     1 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L170                                       |
| 28 |     1 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L181                                       |
| 29 |     1 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L169                                       |
| 30 |     1 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L180                                       |
| 31 |     1 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L183                                       |
| 32 |     1 | `fe25519_add` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L45                                          |
| 33 |     1 | `fe25519_add` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L39                                          |
| 34 |     1 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L272                                         |
| 35 |     1 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L288                                         |
| 36 |     1 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L364                                          |
| 37 |     1 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L366                                          |
| 38 |     1 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L367                                          |
| 39 |     1 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L368                                          |
| 40 |     1 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L375                                          |
| 41 |     1 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L376                                          |
| 42 |     1 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L378                                          |
| 43 |     1 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L379                                          |
| 44 |     1 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L380                                          |
| 45 |     1 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L382                                          |
| 46 |     1 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L383                                          |
| 47 |     1 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L385                                          |
| 48 |     1 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L386                                          |
| 49 |     1 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L388                                          |
| 50 |     1 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L389                                          |
| 51 |     1 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L392                                          |
| 52 |     1 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L394                                          |
| 53 |     1 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L393                                          |
| 54 |     1 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L315                                         |
| 55 |     1 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L314                                         |
| 56 |     1 | `fe25519_sub` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L64                                          |
| 57 |     1 | `fe25519_sub` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L66                                          |
| 58 |     1 | `fe25519_sub` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L69                                          |
| 59 |     1 | `fe25519_sub` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L65                                          |
| 60 |     1 | `fe25519_sq` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L358                                          |
| 61 |     1 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L282                                         |
| 62 |     1 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L283                                         |
| 63 |     1 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L284                                         |
| 64 |     1 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L285                                         |
| 65 |     1 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L304                                         |
| 66 |     1 | `fe25519_mul` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L306                                         |
| 67 |     1 | `fe25519_add` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L38                                          |
| 68 |     1 | `crypto_scalarmult_curve25519` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_scalarmult/curve25519/scalarmult_curve25519.c#L25 (discriminator 3) |


## Computation Reuse (keeping state of first input)
| Id | Count | Line                                                                                                                                                                                 |
|:--:|------:|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1  |   758 | `fe25519_scalar_product` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L502                              |
| 2  |   741 | `fe25519_scalar_product` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L504                              |
| 3  |   701 | `fe25519_scalar_product` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L506                              |
| 4  |   701 | `fe25519_scalar_product` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L508                              |
| 5  |   238 | `crypto_scalarmult_curve25519_ref10` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c#L108               |
| 6  |    10 | `crypto_scalarmult_curve25519_ref10` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c#L109               |
| 7  |     6 | `fe25519_cswap` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h#L148                                       |
| 8  |     2 | `crypto_scalarmult_curve25519` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_scalarmult/curve25519/scalarmult_curve25519.c#L25 (discriminator 3) |
