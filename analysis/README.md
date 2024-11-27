# Analysis
Links in bold have a working attack that leaks the key, given that the attacker can analyze the trace of the given leakage model.
- **[aes_enc-openssl](aes_enc-openssl.md)**
- **[auth-libsodium](auth-libsodium.md)**
- **[x25519-libsodium](x25519-libsodium.md)**
- [curve25519-libsodium](curve25519-libsodium.md)
- [poly1305-libsodium](poly1305-libsodium.md)
- [salsa-libsodium](salsa-libsodium.md)
- [secretbox_easy-libsodium](secretbox_easy-libsodium.md)
- [sha512-libsodium](sha512-libsodium.md)
- [stream_xor-libsodium](stream_xor-libsodium.md)

Attacks are available for the following algorithms and leakage models:
- AES: silent stores (both when [encrypting with a fixed nonce](../src/attack_aes_enc_ssi.py) and when [decrypting with an attacker-chosen nonce](../src/attack_aes_dec_ssi.py))
- auth: [silent stores](../src/attack_auth_ssi.py), [computation reuse](../src/attack_auth_cr.py)
- x25519: [silent stores](../src/attack_x25519_ssi.py), [computation simplification](../src/attack_x25519_cs.py), register file compression ([on 0](../src/attack_x25519_rfc0.py), [on every value](../src/attack_x25519_rfc.py), and [narrow](../src/attack_x25519_nrfc.py)), [narrow computation simplification](./x25519-libsodium.md#narrow-computation-simplification) (attack [here](https://infoscience.epfl.ch/record/223794)).

# Running experiments
The `runner.py` script can be used to run experiments. The following command runs `crypto_auth` from libsodium under every leakage model for 30 seconds, storing every violation found. Inputs are run in batches of two, so it's easier to post-process afterwards. For a better analysis it may better to run longer experiments.
```
david.mateos@AF-519:~/pandora_fuzzing/revizor$ ./src/runner.py save-violations auth libsodium -t 30
[auth libsodium]
ss silent-store SilentStoreOptions(only_initialized_memory=False, restrict_values_to_check=None): 119 violations saved
ssi silent-store SilentStoreOptions(only_initialized_memory=True, restrict_values_to_check=None): 83 violations saved
ssi0 silent-store SilentStoreOptions(only_initialized_memory=True, restrict_values_to_check=[0]): 47 violations saved
rfc register-file-compression RegisterFileCompresionOptions(restrict_values_to_check=None): 41 violations saved
rfc0 register-file-compression RegisterFileCompresionOptions(restrict_values_to_check=[0]): 7 violations saved
nrfc narrow-register-file-compression NarrowRegisterFileCompresionOptions(same_register_allowed=True): 10 violations saved
cs computation-simplification ComputationSimplificationOptions(only_trivial_ops=False): 2 violations saved
cst computation-simplification ComputationSimplificationOptions(only_trivial_ops=True): 1 violations saved
op operand-packing OperandPackingOptions(reservation_update_unit_size=50): 0 violations saved
cr computation-reuse ComputationReuseOptions(n_entries_per_pc=4, reuse_loads=True, reuse_addr_calc=False): 30 violations saved
cra computation-reuse ComputationReuseOptions(n_entries_per_pc=4, reuse_loads=True, reuse_addr_calc=True): 25 violations saved
```
You can also specify `all` as both the algorithm and the library to run the experiment on every algorithm and library. Violations are stored in `violations_db/algorithm-library/leakage_model`.

`runner.py` can also be used with the option `check-safety`. It works the same, but stops when it finds a violation or after the specified timeout. This was used to build the table in [the main readme](../README.md#results-libsodium), while the `save-violations` option was used to build the tables in the analysis folder.

# Post-processing violations
Once we have a bunch of violations, it may be useful to see where they are happening in code. This can be done using the `postprocessor.py` script. For each violation it computes the differences between the traces, translates the resulting program counters into symbols and source lines, and shows the number of occurrences of each of them. In VSCode, you can just Alt+click the link to view the source code.

Here you can see an example of processing the violations found with the previous command.

```
david.mateos@AF-519:~/Desktop/imdea/pandora_fuzzing_dev/revizor$ ./scripts/postprocessor.py violations_db/auth-libsodium/ss/
Read 119 violations in 0.10s
Symbolized 16 unique pcs in 0.01s
Result: 15 unique lines

+-------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Count | Line                                                                                                                                                                        |
+-------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
|   127 | crypto_hash_sha512_update at /home/david.mateos/Desktop/imdea/pandora_fuzzing_dev/revizor/targets/libsodium-1.0.18/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c:238 |
|    94 | crypto_hash_sha512_update at /home/david.mateos/Desktop/imdea/pandora_fuzzing_dev/revizor/targets/libsodium-1.0.18/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c:233 |
|    29 | store64_be at /home/david.mateos/Desktop/imdea/pandora_fuzzing_dev/revizor/targets/libsodium-1.0.18/src/libsodium/./include/sodium/private/common.h:164                     |
|    24 | store64_be at /home/david.mateos/Desktop/imdea/pandora_fuzzing_dev/revizor/targets/libsodium-1.0.18/src/libsodium/./include/sodium/private/common.h:167                     |
|    21 | __memset_sse2_unaligned_erms at ??:?                                                                                                                                        |
|   ... | ...                                                                                                                                                                         |
+-------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
```
It also has a `--markdown` option to show the table in markdown format and replace source references with github links, as shown in the other documents. In addition, the `--pcs` option can be used to list and count PCs instead of just the source code line. Finally, if the binary name is not contained in the folder name, it can be specified with `--binary`.

Another way to see the differences between the two traces of a single violation could be the following:
```
david.mateos@AF-519:~/pandora_fuzzing_dev/revizor$ diff violations/x25519_libsodium_op/0_15.51.49-09-09-22_0x73dfc92921530f36/0_trace violations/x25519_libsodium_op/0_15.51.49-09-09-22_0x73dfc92921530f36/1_trace | ./scripts/symbolizer.py targets/libsodium
292,296c292,305 
< 0x41795b | fe25519_cswap at /home/david.mateos/Desktop/imdea/pandora_fuzzing_dev/revizor/targets/libsodium-1.0.18/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h:181
< 0x417988 | fe25519_cswap at /home/david.mateos/Desktop/imdea/pandora_fuzzing_dev/revizor/targets/libsodium-1.0.18/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h:177
< 0x417914 | fe25519_cswap at /home/david.mateos/Desktop/imdea/pandora_fuzzing_dev/revizor/targets/libsodium-1.0.18/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h:148
< 0x41794f | fe25519_cswap at /home/david.mateos/Desktop/imdea/pandora_fuzzing_dev/revizor/targets/libsodium-1.0.18/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h:171
< 0x418278 | fe25519_add at /home/david.mateos/Desktop/imdea/pandora_fuzzing_dev/revizor/targets/libsodium-1.0.18/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h:39
--- 
> 0x418227 | fe25519_add at /home/david.mateos/Desktop/imdea/pandora_fuzzing_dev/revizor/targets/libsodium-1.0.18/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h:38
> 0x417874 | fe25519_sub at /home/david.mateos/Desktop/imdea/pandora_fuzzing_dev/revizor/targets/libsodium-1.0.18/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h:68
> 0x417899 | fe25519_sub at /home/david.mateos/Desktop/imdea/pandora_fuzzing_dev/revizor/targets/libsodium-1.0.18/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h:72
> 0x417b38 | fe25519_mul at /home/david.mateos/Desktop/imdea/pandora_fuzzing_dev/revizor/targets/libsodium-1.0.18/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h:289
> 0x417b3e | fe25519_mul at /home/david.mateos/Desktop/imdea/pandora_fuzzing_dev/revizor/targets/libsodium-1.0.18/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h:289
```

In some cases this will not be enough to get to the root cause of the violation. In order to get more information about the observations, a detailed trace file is stored along the trace file. This gives details for each obsevation according to the leakage model. For the previous example, for each instruction where Operand Packing happened it states the instruction it was packed with.
```
david.mateos@AF-519:~/pandora_fuzzing_dev/revizor$ cat violations/x25519_libsodium_op/0_15.51.49-09-09-22_0x73dfc92921530f36/0_trace_details | grep "0x41795b:" -A 4
0x41795b: 0x4180db
0x417988: 0x41797d
0x417914: 0x417914
0x41794f: 0x41794c
0x418278: 0x418227
```

Now we can take a look at the disassembly to see which instructions those PCs correspond to. For the second line we can see:
```
  41797d:       4d 31 d5                xor    r13,r10
  417980:       4c 89 69 10             mov    QWORD PTR [rcx+0x10],r13
  417984:       4c 8b 69 18             mov    r13,QWORD PTR [rcx+0x18]
  417988:       4d 31 c5                xor    r13,r8
```
Both xor operations had narrow operands and were packed together.

Note that this detailed trace is not used to detect violations. By default, only differences between normal traces (just PCs) are considered for this. This can be changed setting `CONFIG.verbose_leak = True`, and could represent a stronger threat model.