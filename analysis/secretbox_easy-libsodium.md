# secretbox_easy-libsodium
## Silent Stores
#### On both initialized and uninitialized memory
| Id | Count |                                                                         Line                                                                         |
|:--:|------:|:-----------------------------------------------------------------------------------------------------------------------------------------------------|
| 1  |  4135 | `crypto_secretbox_detached` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_secretbox/crypto_secretbox_easy.c#L54  |
| 2  |  2022 | `stream_ref_xor_ic` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_stream/salsa20/ref/salsa20_ref.c#L90           |
| 3  |    62 | `crypto_core_hsalsa20` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/hsalsa20/ref2/core_hsalsa20_ref2.c#L27 |
| 4  |    26 | `crypto_core_hsalsa20` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/hsalsa20/ref2/core_hsalsa20_ref2.c#L39 |


#### Just on initialized memory
| Id | Count |                                                                         Line                                                                        |
|:--:|------:|:----------------------------------------------------------------------------------------------------------------------------------------------------|
| 1  |  4180 | `crypto_secretbox_detached` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_secretbox/crypto_secretbox_easy.c#L54 |
| 2  |  2059 | `stream_ref_xor_ic` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_stream/salsa20/ref/salsa20_ref.c#L90          |


## Register File Compression
| Id | Count |                                                                          Line                                                                          |
|:--:|------:|:-------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1  | 24040 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L100 |
| 2  | 24040 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L102 |
| 3  | 18030 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L91  |
| 4  | 12020 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L92  |
| 5  | 12020 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L96  |
| 6  | 12020 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L97  |
| 7  | 12020 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L104 |
| 8  | 12020 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L106 |
| 9  | 12020 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L109 |
| 10 | 12020 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L107 |
| 11 | 12020 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L114 |
| 12 | 12020 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L117 |
| 13 | 12020 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L123 |
| 14 | 12020 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L177 |
| 15 | 12020 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L190 |
| 16 | 12020 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L196 |
| 17 | 12020 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L214 |
| 18 |  8977 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L206 |
| 19 |  6010 | `poly1305_init` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L45    |
| 20 |  6010 | `crypto_secretbox_detached` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_secretbox/crypto_secretbox_easy.c#L54    |
| 21 |  6010 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L93  |
| 22 |  6010 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L162 |
| 23 |  6010 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L165 |
| 24 |  6010 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L168 |
| 25 |  6010 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L169 |
| 26 |  6010 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L171 |
| 27 |  6010 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L172 |
| 28 |  6010 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L174 |
| 29 |  6010 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L175 |
| 30 |  6010 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L178 |
| 31 |  6010 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L182 |
| 32 |  6010 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L184 |
| 33 |  6010 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L185 |
| 34 |  6010 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L187 |
| 35 |  6010 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L195 |
| 36 |  6010 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L203 |
| 37 |  6010 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L197 |
| 38 |  6010 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L205 |
| 39 |  3019 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L208 |
| 40 |  3019 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L209 |
| 41 |  1539 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L207 |
| 42 |  1483 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L204 |
| 43 |   142 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L124 |


## Narrow Register File Compression
| Id | Count |                                                                          Line                                                                          |
|:--:|------:|:-------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1  |   842 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L92  |
| 2  |   734 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L106 |
| 3  |   451 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L109 |
| 4  |   416 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L206 |
| 5  |   399 | `poly1305_init` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L45    |
| 6  |   287 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L107 |
| 7  |   221 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L96  |
| 8  |   203 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L101 |
| 9  |    64 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L214 |
| 10 |    37 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L102 |
| 11 |     2 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L122 |
| 12 |     1 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L110 |
| 13 |     1 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L118 |
| 14 |     1 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L105 |
| 15 |     1 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L115 |

## Computation Simplification
| Id | Count |                                                                                  Line                                                                                  |
|:--:|------:|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1  |   736 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L209                 |
| 2  |   726 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L206                 |
| 3  |   329 | `stream_ref_xor_ic` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_stream/salsa20/ref/salsa20_ref.c#L90                             |
| 4  |    70 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L124                 |
| 5  |    14 | `crypto_core_hsalsa20` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/hsalsa20/ref2/core_hsalsa20_ref2.c#L57 (discriminator 3) |
| 6  |    14 | `crypto_core_hsalsa20` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/hsalsa20/ref2/core_hsalsa20_ref2.c#L60 (discriminator 3) |
| 7  |    13 | `crypto_core_hsalsa20` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/hsalsa20/ref2/core_hsalsa20_ref2.c#L63 (discriminator 3) |
| 8  |    13 | `crypto_core_hsalsa20` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/hsalsa20/ref2/core_hsalsa20_ref2.c#L59 (discriminator 3) |
| 9  |    12 | `crypto_core_hsalsa20` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/hsalsa20/ref2/core_hsalsa20_ref2.c#L53 (discriminator 3) |
| 10 |    11 | `crypto_core_hsalsa20` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/hsalsa20/ref2/core_hsalsa20_ref2.c#L51 (discriminator 3) |
| 11 |    11 | `crypto_core_hsalsa20` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/hsalsa20/ref2/core_hsalsa20_ref2.c#L56 (discriminator 3) |
| 12 |    10 | `crypto_core_hsalsa20` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/hsalsa20/ref2/core_hsalsa20_ref2.c#L65 (discriminator 3) |

## Narrow Computation Simplification
| Id | Count | Line                                                                                                                                                   |
|:--:|------:|:-------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1  |     2 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L104 |
| 2  |     1 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L109 |

## Operand Packing
| Id | Count |                                                                          Line                                                                          |
|:--:|------:|:-------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1  |    83 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L107 |
| 2  |     3 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L102 |
| 3  |     2 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L110 |
| 4  |     1 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L105 |
| 5  |     1 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L115 |
| 6  |     1 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L118 |

## Computation Reuse
| Id | Count |                                                                    Line                                                                    |
|:--:|------:|:-------------------------------------------------------------------------------------------------------------------------------------------|
| 1  |  1996 | `stream_ref_xor_ic` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_stream/salsa20/ref/salsa20_ref.c#L90 |

## Computation Reuse (keeping state of first input)
| Id | Count | Line                                                                                                                                       |
|:--:|------:|:-------------------------------------------------------------------------------------------------------------------------------------------|
| 1  |   191 | `stream_ref_xor_ic` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_stream/salsa20/ref/salsa20_ref.c#L90 |