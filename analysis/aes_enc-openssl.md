# aes_enc-openssl
## Silent stores
#### On both initialized and uninitialized memory

| Id | Count |                                                    Line                                                   |
|:--:|------:|:----------------------------------------------------------------------------------------------------------|
| 1  | 11857 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L237             |
| 2  |  1713 | `ShiftRows` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L437           |
| 3  |  1706 | `ShiftRows` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L439           |
| 4  |  1673 | `ShiftRows` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L438           |
| 5  |  1672 | `ShiftRows` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L440           |
| 6  |   662 | `KeyExpansion` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L612        |
| 7  |   520 | `RotWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L593             |
| 8  |   351 | `AddRoundKey` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L529         |
| 9  |   278 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L287             |
| 10 |     2 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L262             |
| 11 |     1 | `AES_set_encrypt_key` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L650 |

#### Just on initialized memory

| Id | Count |                                                Line                                                |
|:--:|------:|:---------------------------------------------------------------------------------------------------|
| 1  | 10046 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L237      |
| 2  |  1401 | `ShiftRows` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L438    |
| 3  |  1391 | `ShiftRows` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L439    |
| 4  |  1390 | `ShiftRows` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L437    |
| 5  |  1368 | `ShiftRows` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L440    |
| 6  |   560 | `KeyExpansion` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L612 |
| 7  |   416 | `RotWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L593      |
| 8  |   275 | `AddRoundKey` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L529  |
| 9  |   222 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L287      |
| 10 |     4 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L262      |

Most violations in `SubLong`, the substitution stage, happen in some `push` instructions at the beginning, so they are not very interesting. There are also two silent stores of temporary intermediate values spilled onto the stack. However, they are 8 bytes long, making it difficult for an attacker to take any advantage of them. This differs from what was described in the Pandora's paper, where they found 8 intermediate values of 2 bytes being spilled onto the stack. It probably depends on compiler version and flags used during compilation.

The violations in `ShiftRows` are interesting. This is its code:
```c
static void ShiftRows(u64 *state)
{
    unsigned char s[4];
    unsigned char *s0;
    int r;

    s0 = (unsigned char *)state;
    for (r = 0; r < 4; r++) {
        s[0] = s0[0*4 + r];
        s[1] = s0[1*4 + r];
        s[2] = s0[2*4 + r];
        s[3] = s0[3*4 + r];
        s0[0*4 + r] = s[(r+0) % 4];
        s0[1*4 + r] = s[(r+1) % 4];
        s0[2*4 + r] = s[(r+2) % 4];
        s0[3*4 + r] = s[(r+3) % 4];
    }
}
```

The function gets optimised into linear control flow without access to the stack. The operation is described in the following image.

![](https://upload.wikimedia.org/wikipedia/commons/thumb/6/66/AES-ShiftRows.svg/800px-AES-ShiftRows.svg.png)

Before the first `ShiftRows`, the state is the input xored with the first key and the IV (all 16 bytes long), to which the operation of byte substitution has been applied. Since these silent stores leak `state[i] = state[j]` for some `i,j`, what we get is:

$$
\begin{align}
&state[i] = state[j] \\\\
&sub(input[i] \oplus key[i]) = sub(input[j] \oplus key[j]) \\\\
&input[i] \oplus key[i] = input[j] \oplus key[j] \\\\
&input[i] \oplus input[j] = key[i] \oplus key[j]
\end{align}
$$

In the threat model of a server that ciphers an attacker input with a secret key, this would leak `key[i] ^ key[j]` for some `i,j`. The values leaked are the following:
```
key[0xd] ^ key[0x1];
key[0x1] ^ key[0x5];
key[0x5] ^ key[0x9];
key[0x9] ^ key[0xd];
key[0x6] ^ key[0xe];
key[0x2] ^ key[0x10];
key[0x10] ^ key[0x2];
key[0xe] ^ tmp[0x6];
key[0x3] ^ key[0xf];
key[0x7] ^ key[0x3];
key[0xb] ^ key[0x7];
key[0xf] ^ key[0xb];
```
I believe we can't know anything else.

However, if silent stores were implemented just when storing a 0, the thing changes:

$$
\begin{align}
&0 = state[i] = state[j] \\\\
&0 = sub(input[i] \oplus key[i] \oplus iv[i]) = sub(input[j] \oplus key[j] \oplus iv[j]) \\\\
&invsub(0) = input[i] \oplus key[i] \oplus iv[i] = input[j] \oplus key[j] \oplus iv[j] \\\\
&key[i] = invsub(0) \oplus input[i] \oplus iv[i], \quad key[j] = invsub(0) \oplus input[j] \oplus iv[j]
\end{align}
$$

It effectively leaks `key[i]` and `key[j]` to the attacker. This leaks 12 out of 16 bytes of the first round key (which is the original key). 4 bytes are not leaked because the first row is not shifted, but it would be easy to bruteforce them offline.

#### Attack
This is the decompilation of the `ShiftRows` function produced by Ghidra:
```c
void ShiftRows(undefined *s0)
{
  undefined tmp1;
  undefined tmp2;
  undefined tmp3;
  
  tmp1 = s0[0xd];
  s0[0xd] = s0[1];
  tmp2 = s0[6];
  s0[1] = s0[5];
  s0[5] = s0[9];
  s0[9] = tmp1;
  tmp1 = s0[2];
  s0[6] = s0[0xe];
  tmp3 = s0[3];
  s0[2] = s0[10];
  s0[10] = tmp1;
  tmp1 = s0[7];
  s0[0xe] = tmp2;
  tmp2 = s0[0xb];
  s0[3] = s0[0xf];
  s0[7] = tmp3;
  s0[0xb] = tmp1;
  s0[0xf] = tmp2;
  return;
}
```

As you can see, there are 12 memory writes:
```c
 1. s0[0xd] = s0[1];
 2. s0[1] = s0[5];
 3. s0[5] = s0[9];
 4. s0[9] = tmp1;
 5. s0[6] = s0[0xe];
 6. s0[2] = s0[10];
 7. s0[10] = tmp1;
 8. s0[0xe] = tmp2;
 9. s0[3] = s0[0xf];
10. s0[7] = tmp3;
11. s0[0xb] = tmp1;
12. s0[0xf] = tmp2;
```
Remember that `s0[i] = input[i] ^ iv[i] ^ key[i]`. Assuming everything else is constant every time (more on that later), silent stores only depend on the input. To start with the first silent store, we must bruteforce bytes 1 and 0xD of the input at the same time. Once we are getting that silent store, in order to get the second one we must bruteforce byte 5. For the third, we need to bruteforce byte 9. At this point, the fourth silent store doesn't give us any information. Then, for silent store number 5, we have to bruteforce bytes 6 and 0xE at the same time, and so on. There will be times when we have to bruteforce two bytes (65536 possibilities) and times when we only have to bruteforce one byte (256 possibilities). Once our input is triggering every silent store, in order to the get the key we apply the following:

$$key[i] = invsub(0) \oplus input[i] \oplus iv[i]$$

Where

$$invsub(0)=82$$

is a constant value.

#### Problem 1: rounds
The first problem is that AES128 performs 10 rounds, each of which calls `ShiftRows`. Silent stores can happen in any round, but we are only interested in the first one. We have no way to tell in which round a silent store happened. Since we are tracking only silent stores on 0, traces are quite short, and most times there isn't a silent store that helps us distinguish whether a silent store happened in the first round or not (more on that [here](#possible-optimization)).

The solution is to assume the silent store happened in the first round, and go for the next one. If, while trying to bruteforce the next byte, that silent store disappears, we know it was not happening in the first round. This is because the state of the first round is only affected by our input, the IV and the key. The IV and the key are assumed constant, and we don't change an input byte once we find its corresponding silent store. Therefore, if a silent store disappears, we discard the previous bruteforced byte and continue from there.

Sometimes we get a silent store with wrong values, and it doesn't disappear afterwards. In that case, we fail to get the next silent store, exhausting all options. When that happens, we discard the wrong values and continue from there.

This can be seen like a tree exploration using depth-first, where the goal is getting to the bottom of the tree (triggering every silent store), and where we can discard branches if we lose some silent store.

The described scenario is exploited [here](../src/attack_aes_enc_ssi.py). It assumes a service that ciphers a given message with a secret key and constant IV, and an attacker that can measure silent stores.


#### Problem 2: IV is not constant
The assumption of the IV being constant is not realistic. In AES CBC, the [IV](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Initialization_vector_(IV)) is supposed to be unpredictable. Despite that, as it is known by the attacker after encryption, he should be able to recover the key using the formula explained earlier. The problem is that we don't know whether a silent store is happening in the first round or not. And now silent stores not only depend on the input, but also on the IV, which changes every time and is controlled by the server. This means we can not apply the previous bruteforcing algorithm.

But not everything is lost: we can apply the same ideas to AES decryption, where a possible attacker controls the ciphertext and the IV, and can keep the latter constant. Similar silent stores happen, but in `InvShiftRows` instead of `ShiftRows`. Now, the initial state is the input xored with the last round key and the IV (no substitution step). Assuming the attacker sets the IV to 0:

$$
\begin{align}
&0 = state[i] = state[j] \\\\
&0 = input[i] \oplus key[i] = input[j] \oplus key[j] \\\\
&key[i] = input[i], \quad key[j] = input[j]
\end{align}
$$

So silent stores will trigger when two input bytes match two key bytes, leaking the key. We still have the problem of not knowing in which round the silent store is happening, but now we can apply the strategy described before because we control the IV. In this case, the leaked key is the last round key. With it, it's possible to recover the original key. Since we can only leak 12 out of 16 bytes of it, we have to bruteforce the other 4. Given a known plaintext and ciphertext, this can be performed offline. The idea is the following:
1. Apply the inverse of the key expansion algorithm to our last round key to get the original key
2. Encrypt the plaintext with the key
3. Check if the resulting ciphertext matches the correct ciphertext
4. If not, continue with the next last round key until we find the correct one

Described attack is implemented [here](../src/attack_aes_dec_ssi.py) (the last round key leak) and [here](../src/attack_aes_dec_ssi_helper.c) (the remaining 4 bytes bruteforce).

#### Possible optimization
Despite we said we can't know if a silent store happened in the first round or not, there could be a way. Before, we were targeting first silent store 1, then silent store 2, and so on. Instead, we can target first the last silent store. That way, once we are triggering the last silent store, every other silent store after it will not belong to the first round. The last silent store would work as a delimiter, and would tell us whether any other silent store happened in the first round or not. This has not been implemented in the script.

## Register File Compression
| Id | Count |                                                Line                                                |
|:--:|------:|:---------------------------------------------------------------------------------------------------|
| 1  | 30199 | `MixColumns` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L479   |
| 2  | 11003 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L310      |
| 3  | 10994 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L317      |
| 4  | 10986 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L315      |
| 5  | 10983 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L241      |
| 6  | 10983 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L319      |
| 7  | 10964 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L269      |
| 8  | 10955 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L313      |
| 9  | 10909 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L275      |
| 10 | 10904 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L256      |
| 11 |  9817 | `MixColumns` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L472   |
| 12 |  5861 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L285      |
| 13 |  5742 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L291      |
| 14 |  5679 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L283      |
| 15 |  5612 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L295      |
| 16 |  5569 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L261      |
| 17 |  5566 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L294      |
| 18 |  5560 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L248      |
| 19 |  5549 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L246      |
| 20 |  5546 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L250      |
| 21 |  5543 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L244      |
| 22 |  5543 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L252      |
| 23 |  5543 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L293      |
| 24 |  5533 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L266      |
| 25 |  5528 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L302      |
| 26 |  5525 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L257      |
| 27 |  5522 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L284      |
| 28 |  5517 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L307      |
| 29 |  5507 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L270      |
| 30 |  5506 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L299      |
| 31 |  5498 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L287      |
| 32 |  5495 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L282      |
| 33 |  5491 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L268      |
| 34 |  5488 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L297      |
| 35 |  5481 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L265      |
| 36 |  5472 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L296      |
| 37 |  5469 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L309      |
| 38 |  5467 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L298      |
| 39 |  5465 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L258      |
| 40 |  5461 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L301      |
| 41 |  5460 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L306      |
| 42 |  5457 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L260      |
| 43 |  5453 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L279      |
| 44 |  5451 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L255      |
| 45 |  5445 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L304      |
| 46 |  5442 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L321      |
| 47 |  5440 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L263      |
| 48 |  5430 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L273      |
| 49 |  4992 | `XtimeLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L93     |
| 50 |  4957 | `MixColumns` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L473   |
| 51 |  4938 | `MixColumns` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L474   |
| 52 |  2572 | `XtimeLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L94     |
| 53 |   335 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L277      |
| 54 |   204 | `KeyExpansion` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L623 |
| 55 |   189 | `MixColumns` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L475   |
| 56 |   163 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L288      |
| 57 |   148 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L276      |
| 58 |   137 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L259      |
| 59 |   127 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L303      |
| 60 |   101 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L262      |
| 61 |    98 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L271      |
| 62 |    95 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L274      |
| 63 |    93 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L300      |
| 64 |    73 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L242      |
| 65 |    69 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L290      |
| 66 |    67 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L267      |
| 67 |    66 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L289      |
| 68 |    66 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L308      |
| 69 |    65 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L292      |
| 70 |    60 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L253      |
| 71 |    60 | `MixColumns` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L478   |
| 72 |    59 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L249      |
| 73 |    53 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L325      |
| 74 |    51 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L286      |
| 75 |    50 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L305      |
| 76 |    47 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L264      |
| 77 |    43 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L243      |
| 78 |    41 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L278      |
| 79 |    33 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L247      |
| 80 |    29 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L245      |
| 81 |    28 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L251      |
| 82 |    26 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L280      |
| 83 |    16 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L320      |
| 84 |    14 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L314      |
| 85 |    13 | `MixColumns` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L470   |
| 86 |    10 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L318      |
| 87 |    10 | `Cipher` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L546       |
| 88 |    10 | `Cipher` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L544       |
| 89 |    10 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L312      |
| 90 |     9 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L311      |
| 91 |     6 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L322      |
| 92 |     6 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L316      |
| 93 |     5 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L323      |
| 94 |     2 | `XtimeLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L91     |
| 95 |     2 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L240      |
| 96 |     1 | `XtimeLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L95     |

## Narrow Register File Compression
| Id | Count |                                               Line                                               |
|:--:|------:|:-------------------------------------------------------------------------------------------------|
| 1  |   691 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L285    |
| 2  |   432 | `XtimeLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L93   |
| 3  |   411 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L287    |
| 4  |   310 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L275    |
| 5  |   300 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L276    |
| 6  |   255 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L266    |
| 7  |   227 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L261    |
| 8  |   208 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L277    |
| 9  |   206 | `XtimeLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L94   |
| 10 |   204 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L307    |
| 11 |   195 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L246    |
| 12 |   186 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L250    |
| 13 |   184 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L244    |
| 14 |   182 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L241    |
| 15 |   176 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L248    |
| 16 |   172 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L319    |
| 17 |   163 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L252    |
| 18 |   161 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L310    |
| 19 |   161 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L259    |
| 20 |   158 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L315    |
| 21 |   157 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L317    |
| 22 |   150 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L294    |
| 23 |   144 | `XtimeLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L91   |
| 24 |   139 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L288    |
| 25 |   137 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L286    |
| 26 |   123 | `MixColumns` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L475 |
| 27 |   122 | `MixColumns` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L474 |
| 28 |   120 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L262    |
| 29 |   111 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L270    |
| 30 |   106 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L302    |
| 31 |    97 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L295    |
| 32 |    96 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L264    |
| 33 |    85 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L265    |
| 34 |    78 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L299    |
| 35 |    77 | `MixColumns` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L479 |
| 36 |    77 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L308    |
| 37 |    74 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L269    |
| 38 |    72 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L274    |
| 39 |    71 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L306    |
| 40 |    58 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L267    |
| 41 |    54 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L249    |
| 42 |    46 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L291    |
| 43 |    43 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L303    |
| 44 |    43 | `MixColumns` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L472 |
| 45 |    41 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L313    |
| 46 |    40 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L300    |
| 47 |    36 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L245    |
| 48 |    36 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L247    |
| 49 |    34 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L260    |
| 50 |    30 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L271    |
| 51 |    28 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L284    |
| 52 |    28 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L253    |
| 53 |    28 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L251    |
| 54 |    26 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L268    |
| 55 |    22 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L325    |
| 56 |    20 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L279    |
| 57 |    20 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L282    |
| 58 |    20 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L289    |
| 59 |    19 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L256    |
| 60 |    19 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L297    |
| 61 |    13 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L305    |
| 62 |    12 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L301    |
| 63 |    11 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L298    |
| 64 |    11 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L320    |
| 65 |    10 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L255    |
| 66 |    10 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L273    |
| 67 |    10 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L278    |
| 68 |    10 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L243    |
| 69 |     9 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L293    |
| 70 |     9 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L322    |
| 71 |     9 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L311    |
| 72 |     8 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L258    |
| 73 |     7 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L309    |
| 74 |     6 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L304    |
| 75 |     5 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L318    |
| 76 |     4 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L314    |
| 77 |     4 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L316    |
| 78 |     4 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L242    |
| 79 |     3 | `XtimeLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L95   |
| 80 |     2 | `MixColumns` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L473 |
| 81 |     1 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L312    |
| 82 |     1 | `MixColumns` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L470 |

## Computation simplification
On both trivial and semi-trivial:
|  Id | Count |                                                Line                                               |
|:---:|------:|:--------------------------------------------------------------------------------------------------|
|  1  |   343 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L194     |
|  2  |   202 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L285     |
|  3  |   180 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L185     |
|  4  |   157 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L186     |
|  5  |   151 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L162     |
|  6  |   148 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L196     |
|  7  |   147 | `MixColumns` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L479  |
|  8  |   134 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L197     |
|  9  |   133 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L177     |
|  10 |   123 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L170     |
|  11 |   122 | `XtimeLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L93    |
|  12 |   122 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L276     |
|  13 |   115 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L224     |
|  14 |   114 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L157     |
|  15 |   114 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L159     |
|  16 |   114 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L175     |
|  17 |   112 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L218     |
|  18 |   105 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L155     |
|  19 |   105 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L277     |
|  20 |   101 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L168     |
|  21 |   100 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L153     |
|  22 |    99 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L228     |
|  23 |    98 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L226     |
|  24 |    98 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L259     |
|  25 |    98 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L287     |
|  26 |    96 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L203     |
|  27 |    96 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L261     |
|  28 |    94 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L219     |
|  29 |    94 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L216     |
|  30 |    93 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L200     |
|  31 |    87 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L248     |
|  32 |    86 | `MixColumns` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L475  |
|  33 |    82 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L150     |
|  34 |    81 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L268     |
|  35 |    80 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L250     |
|  36 |    79 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L204     |
|  37 |    78 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L309     |
|  38 |    77 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L252     |
|  39 |    74 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L266     |
|  40 |    72 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L288     |
|  41 |    71 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L244     |
|  42 |    70 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L315     |
|  43 |    69 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L246     |
|  44 |    69 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L171     |
|  45 |    68 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L307     |
|  46 |    65 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L262     |
|  47 |    64 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L310     |
|  48 |    62 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L241     |
|  49 |    62 | `XtimeLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L95    |
|  50 |    61 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L211     |
|  51 |    61 | `XtimeLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L94    |
|  52 |    60 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L208     |
|  53 |    60 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L294     |
|  54 |    60 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L317     |
|  55 |    55 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L302     |
|  56 |    49 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L158     |
|  57 |    47 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L295     |
|  58 |    47 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L299     |
|  59 |    46 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L319     |
|  60 |    45 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L180     |
|  61 |    44 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L187     |
|  62 |    44 | `XtimeWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L80    |
|  63 |    44 | `MixColumns` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L474  |
|  64 |    44 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L179     |
|  65 |    44 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L249     |
|  66 |    34 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L291     |
|  67 |    34 | `XtimeWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L82    |
|  68 |    32 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L198     |
|  69 |    26 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L303     |
|  70 |    26 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L289     |
|  71 |    24 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L300     |
|  72 |    24 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L209     |
|  73 |    23 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L212     |
|  74 |    22 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L313     |
|  75 |    22 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L222     |
|  76 |    22 | `XtimeWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L81    |
|  77 |    22 | `MixColumns` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L478  |
|  78 |    22 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L191     |
|  79 |    22 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L270     |
|  80 |    20 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L278     |
|  81 |    18 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L183     |
|  82 |    18 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L253     |
|  83 |    18 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L247     |
|  84 |    18 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L264     |
|  85 |    17 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L251     |
|  86 |    16 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L173     |
|  87 |    16 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L192     |
|  88 |    16 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L282     |
|  89 |    15 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L229     |
|  90 |    15 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L160     |
|  91 |    15 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L271     |
|  92 |    15 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L283     |
|  93 |    14 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L245     |
|  94 |    12 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L188     |
|  95 |    11 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L184     |
|  96 |    11 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L156     |
|  97 |    11 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L284     |
|  98 |    10 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L154     |
|  99 |    10 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L297     |
| 100 |    10 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L258     |
| 101 |     9 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L195     |
| 102 |     9 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L256     |
| 103 |     8 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L165     |
| 104 |     8 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L167     |
| 105 |     8 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L243     |
| 106 |     8 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L320     |
| 107 |     7 | `RotWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L593     |
| 108 |     7 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L206     |
| 109 |     7 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L199     |
| 110 |     7 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L152     |
| 111 |     7 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L286     |
| 112 |     6 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L164     |
| 113 |     6 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L166     |
| 114 |     6 | `AES_encrypt` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L676 |
| 115 |     6 | `AES_encrypt` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L669 |
| 116 |     6 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L169     |
| 117 |     6 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L314     |
| 118 |     6 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L318     |
| 119 |     5 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L223     |
| 120 |     4 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L260     |
| 121 |     4 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L306     |
| 122 |     4 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L305     |
| 123 |     4 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L275     |
| 124 |     3 | `MixColumns` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L473  |
| 125 |     3 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L290     |
| 126 |     3 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L316     |
| 127 |     3 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L207     |
| 128 |     3 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L231     |
| 129 |     3 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L308     |
| 130 |     3 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L274     |
| 131 |     2 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L255     |
| 132 |     2 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L257     |
| 133 |     2 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L217     |
| 134 |     2 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L279     |
| 135 |     1 | `XtimeLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L91    |
| 136 |     1 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L221     |
| 137 |     1 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L269     |
| 138 |     1 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L298     |
| 139 |     1 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L301     |
| 140 |     1 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L213     |
| 141 |     1 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L215     |
| 142 |     1 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L311     |
| 143 |     1 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L312     |
| 144 |     1 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L178     |
| 145 |     1 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L304     |
| 146 |     1 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L161     |
| 147 |     1 | `MixColumns` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L472  |

## Operand Packing
| Id | Count |                                                    Line                                                    |
|:--:|------:|:-----------------------------------------------------------------------------------------------------------|
| 1  |   767 | `MixColumns` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L479           |
| 2  |   337 | `XtimeWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L80             |
| 3  |   270 | `XtimeWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L82             |
| 4  |   203 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L196              |
| 5  |   201 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L185              |
| 6  |   161 | `RotWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L593              |
| 7  |   114 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L175              |
| 8  |   112 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L216              |
| 9  |    98 | `KeyExpansion` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L611         |
| 10 |    96 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L179              |
| 11 |    80 | `XtimeLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L94             |
| 12 |    66 | `CRYPTO_cbc128_encrypt` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/modes/cbc128.c#L47 |
| 13 |    57 | `XtimeLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L93             |
| 14 |    48 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L171              |
| 15 |    48 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L276              |
| 16 |    47 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L194              |
| 17 |    45 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L287              |
| 18 |    44 | `AES_encrypt` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L669          |
| 19 |    40 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L198              |
| 20 |    39 | `MixColumns` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L475           |
| 21 |    39 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L203              |
| 22 |    36 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L197              |
| 23 |    35 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L270              |
| 24 |    32 | `AES_set_encrypt_key` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L652  |
| 25 |    30 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L170              |
| 26 |    22 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L266              |
| 27 |    22 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L183              |
| 28 |    21 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L177              |
| 29 |    21 | `AES_encrypt` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L676          |
| 30 |    20 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L307              |
| 31 |    19 | `Cipher` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L554               |
| 32 |    17 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L262              |
| 33 |    16 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L285              |
| 34 |    14 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L294              |
| 35 |    13 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L186              |
| 36 |    13 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L299              |
| 37 |    12 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L211              |
| 38 |    12 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L268              |
| 39 |    11 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L208              |
| 40 |    11 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L188              |
| 41 |    10 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L289              |
| 42 |    10 | `MixColumns` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L474           |
| 43 |     8 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L212              |
| 44 |     7 | `aes_enc` at ??#L?                                                                                         |
| 45 |     7 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L218              |
| 46 |     6 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L187              |
| 47 |     6 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L261              |
| 48 |     5 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L162              |
| 49 |     5 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L204              |
| 50 |     4 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L277              |
| 51 |     4 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L288              |
| 52 |     4 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L295              |
| 53 |     4 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L302              |
| 54 |     3 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L241              |
| 55 |     3 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L246              |
| 56 |     3 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L250              |
| 57 |     3 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L303              |
| 58 |     3 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L274              |
| 59 |     2 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L168              |
| 60 |     2 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L180              |
| 61 |     2 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L256              |
| 62 |     2 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L258              |
| 63 |     2 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L282              |
| 64 |     2 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L291              |
| 65 |     2 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L300              |
| 66 |     2 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L309              |
| 67 |     2 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L313              |
| 68 |     2 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L317              |
| 69 |     2 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L217              |
| 70 |     2 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L213              |
| 71 |     2 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L304              |
| 72 |     1 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L243              |
| 73 |     1 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L247              |
| 74 |     1 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L251              |
| 75 |     1 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L255              |
| 76 |     1 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L259              |
| 77 |     1 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L260              |
| 78 |     1 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L263              |
| 79 |     1 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L271              |
| 80 |     1 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L293              |
| 81 |     1 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L296              |
| 82 |     1 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L297              |
| 83 |     1 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L305              |
| 84 |     1 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L310              |
| 85 |     1 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L315              |
| 86 |     1 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L319              |
| 87 |     1 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L321              |
| 88 |     1 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L314              |
| 89 |     1 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L318              |
| 90 |     1 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L322              |
| 91 |     1 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L264              |
| 92 |     1 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L173              |
| 93 |     1 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L209              |
| 94 |     1 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L214              |
| 95 |     1 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L229              |
| 96 |     1 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L279              |

## Computation Reuse
Reusing address calculation:
| Id | Count |                                                Line                                                |
|:--:|------:|:---------------------------------------------------------------------------------------------------|
| 1  |   320 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L185      |
| 2  |   274 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L196      |
| 3  |   152 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L287      |
| 4  |   142 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L200      |
| 5  |   140 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L276      |
| 6  |    74 | `XtimeLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L93     |
| 7  |    68 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L175      |
| 8  |    49 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L194      |
| 9  |    46 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L216      |
| 10 |    44 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L285      |
| 11 |    42 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L201      |
| 12 |    41 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L291      |
| 13 |    38 | `KeyExpansion` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L623 |
| 14 |    37 | `XtimeLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L94     |
| 15 |    32 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L270      |
| 16 |    28 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L266      |
| 17 |    24 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L179      |
| 18 |    21 | `KeyExpansion` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L622 |
| 19 |    19 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L277      |
| 20 |    18 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L288      |
| 21 |    18 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L284      |
| 22 |    17 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L204      |
| 23 |    16 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L186      |
| 24 |    14 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L289      |
| 25 |    13 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L295      |
| 26 |    13 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L292      |
| 27 |    13 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L197      |
| 28 |    13 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L198      |
| 29 |    12 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L307      |
| 30 |    12 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L274      |
| 31 |     9 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L170      |
| 32 |     8 | `RotWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L593      |
| 33 |     6 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L261      |
| 34 |     6 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L183      |
| 35 |     6 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L193      |
| 36 |     4 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L271      |
| 37 |     4 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L275      |
| 38 |     4 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L278      |
| 39 |     4 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L279      |
| 40 |     4 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L162      |
| 41 |     4 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L300      |
| 42 |     3 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L258      |
| 43 |     3 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L286      |
| 44 |     3 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L290      |
| 45 |     3 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L168      |
| 46 |     3 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L282      |
| 47 |     3 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L294      |
| 48 |     3 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L195      |
| 49 |     2 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L259      |
| 50 |     2 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L296      |
| 51 |     2 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L180      |
| 52 |     2 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L184      |
| 53 |     2 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L187      |
| 54 |     2 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L188      |
| 55 |     1 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L320      |
| 56 |     1 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L203      |
| 57 |     1 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L283      |
| 58 |     1 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L293      |
| 59 |     1 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L152      |
| 60 |     1 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L245      |
| 61 |     1 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L241      |
| 62 |     1 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L244      |
| 63 |     1 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L246      |
| 64 |     1 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L248      |
| 65 |     1 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L252      |
| 66 |     1 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L319      |
| 67 |     1 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L199      |


## Computation Reuse (keeping state of first input)
| Id | Count | Line                                                                                               |
|:--:|------:|:---------------------------------------------------------------------------------------------------|
| 1  |   278 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L185      |
| 2  |   248 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L196      |
| 3  |   132 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L200      |
| 4  |   120 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L287      |
| 5  |    88 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L276      |
| 6  |    84 | `XtimeLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L93     |
| 7  |    60 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L175      |
| 8  |    57 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L194      |
| 9  |    42 | `XtimeLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L94     |
| 10 |    36 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L216      |
| 11 |    36 | `XtimeWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L80     |
| 12 |    35 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L201      |
| 13 |    34 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L179      |
| 14 |    32 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L266      |
| 15 |    26 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L197      |
| 16 |    26 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L198      |
| 17 |    26 | `KeyExpansion` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L623 |
| 18 |    21 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L285      |
| 19 |    20 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L186      |
| 20 |    20 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L291      |
| 21 |    18 | `XtimeWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L81     |
| 22 |    18 | `KeyExpansion` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L615 |
| 23 |    16 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L307      |
| 24 |    16 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L270      |
| 25 |    15 | `KeyExpansion` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L622 |
| 26 |    13 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L203      |
| 27 |    12 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L162      |
| 28 |    11 | `RotWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L593      |
| 29 |     9 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L183      |
| 30 |     9 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L193      |
| 31 |     9 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L204      |
| 32 |     8 | `Cipher` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L545       |
| 33 |     7 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L195      |
| 34 |     6 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L292      |
| 35 |     6 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L261      |
| 36 |     6 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L288      |
| 37 |     6 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L289      |
| 38 |     6 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L284      |
| 39 |     4 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L295      |
| 40 |     3 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L180      |
| 41 |     3 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L184      |
| 42 |     3 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L187      |
| 43 |     3 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L188      |
| 44 |     3 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L199      |
| 45 |     3 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L168      |
| 46 |     3 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L262      |
| 47 |     3 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L299      |
| 48 |     3 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L274      |
| 49 |     3 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L277      |
| 50 |     2 | `SubWord` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L171      |
| 51 |     2 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L264      |
| 52 |     2 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L259      |
| 53 |     1 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L271      |
| 54 |     1 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L275      |
| 55 |     1 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L278      |
| 56 |     1 | `SubLong` at https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L279      |

CRs in `SubWord` might be interesting. That function is called from [`KeyExpansion`](https://github.com/openssl/openssl/blob/openssl-3.0.5/crypto/aes/aes_core.c#L615). It is first called with the last 4 bytes of the key as argument. Despite it's 32 bits, some operations may be performed with a subset of those, making it easier to bruteforce for an attacker.