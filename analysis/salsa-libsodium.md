# salsa-libsodium
## Silent Stores
| Id | Count |                                                                    Line                                                                   |
|:--:|------:|:------------------------------------------------------------------------------------------------------------------------------------------|
| 1  |   722 | `crypto_core_salsa` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/salsa/ref/core_salsa_ref.c#L31 |
| 2  |   189 | `crypto_core_salsa` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/salsa/ref/core_salsa_ref.c#L34 |
| 3  |   186 | `crypto_core_salsa` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/salsa/ref/core_salsa_ref.c#L45 |
| 4  |   183 | `crypto_core_salsa` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/salsa/ref/core_salsa_ref.c#L35 |
| 5  |   183 | `crypto_core_salsa` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/salsa/ref/core_salsa_ref.c#L37 |
| 6  |   182 | `crypto_core_salsa` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/salsa/ref/core_salsa_ref.c#L33 |
| 7  |   176 | `crypto_core_salsa` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/salsa/ref/core_salsa_ref.c#L21 |
| 8  |   175 | `crypto_core_salsa` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/salsa/ref/core_salsa_ref.c#L32 |

We can see most violations occur when loading the key from memory into local variables. Some of these local variables seem to be in the stack, causing the key to be spilled to the stack. This causes silent stores when the key matches whatever was in the stack before. Since these local variables are not cleared at the end of the function, this could leak the key used in a previous call. We can confirm this happens running revizor with `keep_state_of_first_input=True`: it detects a violation when a key which shares part of the first key is generated.

## Computation Simplification
| Id | Count |                                                                             Line                                                                            |
|:--:|------:|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1  |   200 | `crypto_core_salsa` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/salsa/ref/core_salsa_ref.c#L45 (discriminator 3) |
| 2  |    92 | `crypto_core_salsa` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/salsa/ref/core_salsa_ref.c#L60 (discriminator 3) |
| 3  |    92 | `crypto_core_salsa` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/salsa/ref/core_salsa_ref.c#L90                   |
| 4  |    89 | `crypto_core_salsa` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/salsa/ref/core_salsa_ref.c#L48 (discriminator 3) |
| 5  |    89 | `crypto_core_salsa` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/salsa/ref/core_salsa_ref.c#L55 (discriminator 3) |
| 6  |    89 | `crypto_core_salsa` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/salsa/ref/core_salsa_ref.c#L91                   |
| 7  |    89 | `crypto_core_salsa` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/salsa/ref/core_salsa_ref.c#L81                   |
| 8  |    89 | `crypto_core_salsa` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/salsa/ref/core_salsa_ref.c#L54 (discriminator 3) |
| 9  |    89 | `crypto_core_salsa` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/salsa/ref/core_salsa_ref.c#L93                   |
| 10 |    88 | `crypto_core_salsa` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/salsa/ref/core_salsa_ref.c#L46 (discriminator 3) |
| 11 |    88 | `crypto_core_salsa` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/salsa/ref/core_salsa_ref.c#L83                   |
| 12 |    87 | `crypto_core_salsa` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/salsa/ref/core_salsa_ref.c#L52 (discriminator 3) |
| 13 |    87 | `crypto_core_salsa` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/salsa/ref/core_salsa_ref.c#L58 (discriminator 3) |
| 14 |    87 | `crypto_core_salsa` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/salsa/ref/core_salsa_ref.c#L80                   |
| 15 |    87 | `crypto_core_salsa` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/salsa/ref/core_salsa_ref.c#L82                   |
| 16 |    86 | `crypto_core_salsa` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/salsa/ref/core_salsa_ref.c#L51 (discriminator 3) |
| 17 |    86 | `crypto_core_salsa` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/salsa/ref/core_salsa_ref.c#L92                   |
| 18 |     2 | `crypto_core_salsa` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/salsa/ref/core_salsa_ref.c#L86                   |

## Operand Packing
| Id | Count |    PC    | Line                                                                                                                                      |
|:--:|------:|:--------:|:------------------------------------------------------------------------------------------------------------------------------------------|
| 1  |     1 | 0x402b94 | `crypto_core_salsa` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/salsa/ref/core_salsa_ref.c#L81 |
| 2  |     1 | 0x402bc5 | `crypto_core_salsa` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/salsa/ref/core_salsa_ref.c#L86 |

Both violations happen at the `add` instruction in their respective lines: `x2  + j2` and `x7  + j7`. For example, the first one is translated as:
```
  402b90:       8b 4c 24 cc             mov    ecx,DWORD PTR [rsp-0x34]
  402b94:       03 4c 24 98             add    ecx,DWORD PTR [rsp-0x68]
```

The `trace_details` file indicates with which other instruction is the `add` packed with:
```
david.mateos@AF-519:~/Desktop/imdea/pandora_fuzzing_dev/revizor$ cat violations/salsa_libsodium_op/1_23.07.44-09-09-22_0x94fd9e44043d6fb/46_trace_details
0x402b94: 0x402b3a
david.mateos@AF-519:~/Desktop/imdea/pandora_fuzzing_dev/revizor$ \cat violations/salsa_libsodium_op/0_17.43.01-09-09-22_0x4f6f42fbd4a78bdb/6_trace_details
0x402bc5: 0x402b3a
```

Both observations happen because the `add` instructions are packed with the `i += 2` operation of the [loop](https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_core/salsa/ref/core_salsa_ref.c#L45), which is translated as:
```
  402b3a:       83 44 24 90 02          add    DWORD PTR [rsp-0x70],0x2
```

I'm not sure why we are not getting violations with the packing of the `i += 2` and the additions from inside the loop. Since these violations seem to be rather unlikely, maybe it just needs more time.