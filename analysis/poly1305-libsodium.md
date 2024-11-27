# poly1305-libsodium
## Silent Stores
#### On both initialized and uninitialized memory
| Id | Count |                                                                          Line                                                                          |
|:--:|------:|:-------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1  |  1283 | `__memset_sse2_unaligned_erms` at ??#L?                                                                                                                |
| 2  |   249 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L118 |
| 3  |   202 | `poly1305_init` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L46    |
| 4  |   202 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L75  |
| 5  |   202 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L82  |
| 6  |   190 | `poly1305_init` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L44    |
| 7  |   190 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L73  |
| 8  |   179 | `poly1305_init` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L45    |
| 9  |   179 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L74  |
| 10 |   179 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L81  |
| 11 |   175 | `poly1305_init` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L55    |
| 12 |   174 | `poly1305_init` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L54    |
| 13 |   121 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L130 |
| 14 |   121 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L131 |
| 15 |   121 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L132 |
| 16 |    71 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L214 |
| 17 |    70 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L213 |

The memset silent stores are probably not interesting, since they are most likely clearing memory.

In `poly1305_init` (entries 3, 6, 8, 11, 12), writing to `st->r` and `st->pad` is causing silent stores. In `st->r`, the values written depend directly on the first half of the key, while in `st->pad` the values written are exactly the second half of the key. However, since `st` [is being cleared](https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L220) in `poly1305_finish`, these silent stores happen when these 64-bit words inside the key are 0, which is not quite interesting.

In `poly1305_blocks` (entries 4, 5, 7, ...), there are silent stores when reading from `st->r` into local variables. This is interesting because these local variables are not cleared, so we are in another instance of key-dependant values being spilled to the stack. When a silent store happens, it leaks the value stored there in a previous run. However, since the values spilled are 8 bytes long, it would be difficult for an attacker to bruteforce them.

Finally, the silent stores in `poly1305_finish` (entries 16, 17) happen when storing `h0, h1` into the result `mac`. Since they are writes to the output buffer, the same as in [stream_xor-libsodium](#stream_xor-libsodium) applies here.


#### Just on initialized memory
| Id | Count |                                                                          Line                                                                          |
|:--:|------:|:-------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1  |  1140 | `__memset_sse2_unaligned_erms` at ??#L?                                                                                                                |
| 2  |   121 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L118 |
| 3  |   120 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L130 |
| 4  |   120 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L131 |
| 5  |   120 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L132 |

Here we can see the silent stores that happen when saving local vars `h0, h1, h2` into `st->h` are producing violations. Since `st->h` was [initialized to zero](https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L77) in `poly1305_blocks`, these silent stores happen when the result of `poly1305_blocks` is also zero. In this case, this is happening when the key is just null bytes, but maybe it can happen in other situations as well.

## Register File Compression
| Id | Count |                                                                                  Line                                                                                 |
|:--:|------:|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1  | 80269 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L100                |
| 2  | 79931 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L102                |
| 3  | 40322 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L96                 |
| 4  | 40154 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L97                 |
| 5  | 40051 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L117                |
| 6  | 40050 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L114                |
| 7  | 40042 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L123                |
| 8  | 40042 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L190                |
| 9  | 40034 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L214                |
| 10 | 40006 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L104                |
| 11 | 39995 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L196                |
| 12 | 39948 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L177                |
| 13 | 31131 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L206                |
| 14 | 20299 | `poly1305_init` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L45                   |
| 15 | 20261 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L109                |
| 16 | 20260 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L107                |
| 17 | 20249 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L106                |
| 18 | 20175 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L203                |
| 19 | 20090 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L175                |
| 20 | 20070 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L182                |
| 21 | 20070 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L185                |
| 22 | 20024 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L165                |
| 23 | 20021 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L162                |
| 24 | 20021 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L168                |
| 25 | 20021 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L171                |
| 26 | 20021 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L195                |
| 27 | 20021 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L197                |
| 28 | 20020 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L205                |
| 29 | 19974 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L169                |
| 30 | 19974 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L172                |
| 31 | 19974 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L174                |
| 32 | 19974 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L178                |
| 33 | 19974 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L184                |
| 34 | 19974 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L187                |
| 35 | 10118 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L200                |
| 36 | 10067 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L209                |
| 37 |  9915 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L208                |
| 38 |  9881 | `poly1305_init` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L41                   |
| 39 |  5078 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L204                |
| 40 |  5033 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L207                |
| 41 |   890 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L124                |
| 42 |   808 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L122                |
| 43 |   394 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L101                |
| 44 |   394 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L110                |
| 45 |   359 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L201                |
| 46 |   350 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L133                |
| 47 |   244 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L99                 |
| 48 |   222 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L118                |
| 49 |   211 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L115                |
| 50 |   209 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L105                |
| 51 |   200 | `poly1305_init` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L46                   |
| 52 |   188 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L121                |
| 53 |   163 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L166                |
| 54 |   152 | `poly1305_update` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna.c#L21                   |
| 55 |   152 | `poly1305_update` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna.c#L46                   |
| 56 |   152 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L191                |
| 57 |   152 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L192                |
| 58 |   152 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L193                |
| 59 |   152 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L221                |
| 60 |   132 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L82                 |
| 61 |   130 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L79                 |
| 62 |   130 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L78                 |
| 63 |   130 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L81                 |
| 64 |   121 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L213                |
| 65 |   118 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L144                |
| 66 |   116 | `poly1305_update` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna.c#L56                   |
| 67 |   116 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L161                |
| 68 |   116 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L164                |
| 69 |   116 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L167                |
| 70 |   116 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L170                |
| 71 |   116 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L173                |
| 72 |   116 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L176                |
| 73 |   106 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L120                |
| 74 |    94 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L113                |
| 75 |    94 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L116                |
| 76 |    94 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L119                |
| 77 |    76 | `poly1305_init` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L44                   |
| 78 |    71 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L92                 |
| 79 |    70 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L73                 |
| 80 |    66 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L75                 |
| 81 |    65 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L74                 |
| 82 |    65 | `crypto_onetimeauth_poly1305_donna` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna.c#L62 |
| 83 |    62 | `poly1305_init` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L54                   |
| 84 |    56 | `poly1305_init` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L55                   |
| 85 |    56 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L93                 |
| 86 |    54 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L91                 |
| 87 |    50 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L163                |
| 88 |    47 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L158                |
| 89 |    16 | `poly1305_update` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna.c#L42                   |
| 90 |    10 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L89                 |
| 91 |     8 | `crypto_onetimeauth_poly1305_donna` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna.c#L66 |
| 92 |     8 | `poly1305_update` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna.c#L17                   |
| 93 |     8 | `poly1305_update` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna.c#L44                   |
| 94 |     4 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L88                 |
| 95 |     1 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L66                 |

## Narrow Register File Compression
| Id | Count |                                                                                  Line                                                                                 |
|:--:|------:|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1  |  2986 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L106                |
| 2  |  2236 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L206                |
| 3  |  2189 | `poly1305_init` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L45                   |
| 4  |  2071 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L109                |
| 5  |  1996 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L107                |
| 6  |  1432 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L96                 |
| 7  |  1249 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L101                |
| 8  |  1011 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L102                |
| 9  |   712 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L100                |
| 10 |   648 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L97                 |
| 11 |   448 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L214                |
| 12 |   386 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L99                 |
| 13 |   385 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L110                |
| 14 |   385 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L118                |
| 15 |   384 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L104                |
| 16 |   380 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L105                |
| 17 |   380 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L115                |
| 18 |   306 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L121                |
| 19 |   285 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L114                |
| 20 |   283 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L203                |
| 21 |   279 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L209                |
| 22 |   277 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L123                |
| 23 |   276 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L117                |
| 24 |   222 | `poly1305_init` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L46                   |
| 25 |   217 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L81                 |
| 26 |   216 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L82                 |
| 27 |   207 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L196                |
| 28 |   181 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L119                |
| 29 |   180 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L116                |
| 30 |   170 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L113                |
| 31 |   154 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L213                |
| 32 |   140 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L165                |
| 33 |   140 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L168                |
| 34 |   140 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L177                |
| 35 |   140 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L195                |
| 36 |   140 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L197                |
| 37 |   139 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L120                |
| 38 |   138 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L124                |
| 39 |   138 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L162                |
| 40 |   138 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L171                |
| 41 |   130 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L205                |
| 42 |   112 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L75                 |
| 43 |   110 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L74                 |
| 44 |   108 | `poly1305_init` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L44                   |
| 45 |   108 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L73                 |
| 46 |   103 | `poly1305_init` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L54                   |
| 47 |   103 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L200                |
| 48 |    97 | `crypto_onetimeauth_poly1305_donna` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna.c#L62 |
| 49 |    95 | `poly1305_init` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L41                   |
| 50 |    92 | `poly1305_init` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L55                   |
| 51 |    92 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L201                |
| 52 |    70 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L163                |
| 53 |    70 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L166                |
| 54 |    70 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L172                |
| 55 |    70 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L174                |
| 56 |    70 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L175                |
| 57 |    70 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L181                |
| 58 |    70 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L182                |
| 59 |    70 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L190                |
| 60 |    69 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L158                |
| 61 |    69 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L169                |
| 62 |    69 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L178                |
| 63 |    69 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L184                |
| 64 |    69 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L185                |
| 65 |    55 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L208                |
| 66 |     1 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L91                 |
| 67 |     1 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L92                 |

## Computation Simplification
| Id | Count |                                                                          Line                                                                          |
|:--:|------:|:-------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1  |  5765 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L206 |
| 2  |  5675 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L209 |
| 3  |   904 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L124 |
| 4  |   372 | `poly1305_init` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L45    |
| 5  |   334 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L104 |
| 6  |   328 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L99  |
| 7  |   328 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L107 |
| 8  |   224 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L203 |
| 9  |   174 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L100 |
| 10 |   174 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L105 |
| 11 |   174 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L110 |
| 12 |   160 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L97  |
| 13 |   160 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L106 |
| 14 |   154 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L96  |
| 15 |   154 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L102 |
| 16 |   154 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L109 |
| 17 |   154 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L101 |
| 18 |   150 | `poly1305_init` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L46    |
| 19 |   141 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L213 |
| 20 |   133 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L121 |
| 21 |   131 | `poly1305_init` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L44    |
| 22 |   120 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L114 |
| 23 |   120 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L115 |
| 24 |   120 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L117 |
| 25 |   120 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L118 |
| 26 |   120 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L120 |
| 27 |   120 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L122 |
| 28 |   120 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L123 |
| 29 |   120 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L195 |
| 30 |   120 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L196 |
| 31 |   120 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L197 |
| 32 |    99 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L214 |
| 33 |    80 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L82  |
| 34 |    77 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L81  |
| 35 |    72 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L66  |
| 36 |    60 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L91  |
| 37 |    60 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L93  |
| 38 |    60 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L92  |
| 39 |    60 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L161 |
| 40 |    60 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L164 |
| 41 |    60 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L162 |
| 42 |    60 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L165 |
| 43 |    60 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L167 |
| 44 |    60 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L168 |
| 45 |    60 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L170 |
| 46 |    60 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L171 |
| 47 |    60 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L174 |
| 48 |    60 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L173 |
| 49 |    60 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L187 |
| 50 |    60 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L176 |
| 51 |    60 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L177 |
| 52 |    60 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L185 |
| 53 |    45 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L204 |
| 54 |    45 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L205 |
| 55 |    39 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L208 |
| 56 |    39 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L207 |

## Narrow Computation Simplification
| Id | Count | Line                                                                                                                                                   |
|:--:|------:|:-------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1  |   105 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L104 |
| 2  |   105 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L109 |
| 3  |   104 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L99  |
| 4  |    74 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L97  |
| 5  |    74 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L102 |
| 6  |    74 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L107 |
| 7  |    46 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L106 |
| 8  |    27 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L96  |
| 9  |    27 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L101 |


## Operand Packing
| Id | Count |                                                                                  Line                                                                                 |
|:--:|------:|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1  |   348 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L105                |
| 2  |   323 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L110                |
| 3  |   305 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L118                |
| 4  |   296 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L100                |
| 5  |   126 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L209                |
| 6  |   122 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L124                |
| 7  |   102 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L206                |
| 8  |    91 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L115                |
| 9  |    87 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L81                 |
| 10 |    76 | `crypto_onetimeauth_poly1305_donna` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna.c#L70 |
| 11 |    76 | `__explicit_bzero_chk_internal` at ??#L?                                                                                                                              |
| 12 |    70 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L213                |
| 13 |    62 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L170                |
| 14 |    62 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L178                |
| 15 |    62 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L201                |
| 16 |    61 | `poly1305_init` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L46                   |
| 17 |    61 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L122                |
| 18 |    61 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L164                |
| 19 |    61 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L166                |
| 20 |    61 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L172                |
| 21 |    61 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L176                |
| 22 |    61 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L185                |
| 23 |    61 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L195                |
| 24 |    60 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L197                |
| 25 |    49 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L203                |
| 26 |    44 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L214                |
| 27 |    38 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L204                |
| 28 |    28 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L207                |
| 29 |    13 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L107                |
| 30 |     9 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L99                 |
| 31 |     8 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L104                |
| 32 |     4 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L82                 |
| 33 |     2 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L102                |
| 34 |     1 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L196                |
| 35 |     1 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L169                |
| 36 |     1 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L182                |
| 37 |     1 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L97                 |

## Computation Reuse
| Id | Count |                                                                          Line                                                                          |
|:--:|------:|:-------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1  |   177 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L107 |
| 2  |   118 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L110 |
| 3  |   118 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L118 |
| 4  |   117 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L105 |
| 5  |   117 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L115 |
| 6  |   116 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L100 |
| 7  |   104 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L97  |
| 8  |   103 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L102 |
| 9  |   100 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L99  |
| 10 |    97 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L104 |
| 11 |    53 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L122 |
| 12 |    53 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L123 |
| 13 |    52 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L114 |
| 14 |    52 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L117 |
| 15 |    52 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L120 |
| 16 |    52 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L121 |
| 17 |    52 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L124 |
| 18 |    40 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L93  |
| 19 |    40 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L109 |
| 20 |    34 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L92  |
| 21 |    30 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L91  |
| 22 |    30 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L96  |
| 23 |    30 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L101 |
| 24 |    30 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L106 |

## Computation Reuse (keeping state of first input)
| Id | Count | Line                                                                                                                                                   |
|:--:|------:|:-------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1  |   123 | `poly1305_init` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L45    |
| 2  |    90 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L206 |
| 3  |    70 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L107 |
| 4  |    66 | `poly1305_init` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L46    |
| 5  |    49 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L102 |
| 6  |    47 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L97  |
| 7  |    44 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L110 |
| 8  |    43 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L104 |
| 9  |    43 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L105 |
| 10 |    43 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L115 |
| 11 |    43 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L118 |
| 12 |    42 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L99  |
| 13 |    42 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L100 |
| 14 |    40 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L82  |
| 15 |    37 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L81  |
| 16 |    34 | `poly1305_init` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L44    |
| 17 |    33 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L203 |
| 18 |    30 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L66  |
| 19 |    28 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L209 |
| 20 |    21 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L101 |
| 21 |    20 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L106 |
| 22 |    20 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L96  |
| 23 |    20 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L109 |
| 24 |    17 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L114 |
| 25 |    17 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L117 |
| 26 |    17 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L120 |
| 27 |    17 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L121 |
| 28 |    17 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L122 |
| 29 |    17 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L123 |
| 30 |    17 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L124 |
| 31 |    14 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L187 |
| 32 |    14 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L201 |
| 33 |    14 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L195 |
| 34 |    14 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L196 |
| 35 |    14 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L197 |
| 36 |     9 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L91  |
| 37 |     9 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L93  |
| 38 |     9 | `poly1305_blocks` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L92  |
| 39 |     8 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L213 |
| 40 |     7 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L161 |
| 41 |     7 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L163 |
| 42 |     7 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L164 |
| 43 |     7 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L162 |
| 44 |     7 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L166 |
| 45 |     7 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L165 |
| 46 |     7 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L167 |
| 47 |     7 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L169 |
| 48 |     7 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L168 |
| 49 |     7 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L170 |
| 50 |     7 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L172 |
| 51 |     7 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L171 |
| 52 |     7 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L174 |
| 53 |     7 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L173 |
| 54 |     7 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L175 |
| 55 |     7 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L176 |
| 56 |     7 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L177 |
| 57 |     7 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L178 |
| 58 |     7 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L182 |
| 59 |     7 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L184 |
| 60 |     7 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L185 |
| 61 |     7 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L190 |
| 62 |     7 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L193 |
| 63 |     4 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L204 |
| 64 |     4 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L205 |
| 65 |     3 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L214 |
| 66 |     2 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L208 |
| 67 |     2 | `poly1305_finish` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h#L207 |

Apart from the CRs in `poly1305_blocks`, there are also some in `poly1305_init`. They are happening here:
```c
    t0 = LOAD64_LE(&key[0]);
    t1 = LOAD64_LE(&key[8]);
    st->r[0] = (t0) & 0xffc0fffffff;
    st->r[1] = ((t0 >> 44) | (t1 << 20)) & 0xfffffc0ffff;
    st->r[2] = ((t1 >> 24)) & 0x00ffffffc0f;
```
The Reuse Buffer is pre-initialised with the results for those operations for the `t0` and `t1` of a previous key. If an attacker can perform the same operations with a controlled key, knowing if CR happens or not leaks whether its corresponding `t0` and `t1` match the previous ones. However, since they are 8 bytes long, it would be difficult to bruteforce. Note that not every operations requires bruteforcing the full `t0` and `t1`. For example, the AND operation in the last line only requires bruteforcing `t1`'s 40 most significant bits, which is still too much.