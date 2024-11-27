## symbolizer.py
Usage:
```
./scripts/symbolizer.py binary_path [trace_file]
```

This script takes a binary and a trace file. The trace file is a text file with a program counter each line (like the one stored by revizor). It outputs the trace file, adding to each line the symbol the PC corresponds to in the binary. The binary needs to be built with debug information. If no trace file is provided, it reads from stdin instead.

```
david.mateos@AF-519:~/Desktop/imdea/pandora_fuzzing_dev/revizor$ \cat /tmp/test
0x417943
0x417946
0x417949
0x41794c
david.mateos@AF-519:~/Desktop/imdea/pandora_fuzzing_dev/revizor$ ./scripts/symbolizer.py targets/libsodium /tmp/test 
0x417943 | fe25519_cswap at /home/david.mateos/Desktop/imdea/pandora_fuzzing_dev/revizor/targets/libsodium-1.0.18/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h:168
0x417946 | fe25519_cswap at /home/david.mateos/Desktop/imdea/pandora_fuzzing_dev/revizor/targets/libsodium-1.0.18/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h:169
0x417949 | fe25519_cswap at /home/david.mateos/Desktop/imdea/pandora_fuzzing_dev/revizor/targets/libsodium-1.0.18/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h:166
0x41794c | fe25519_cswap at /home/david.mateos/Desktop/imdea/pandora_fuzzing_dev/revizor/targets/libsodium-1.0.18/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h:170
david.mateos@AF-519:~/Desktop/imdea/pandora_fuzzing_dev/revizor$ cat /tmp/test | ./scripts/symbolizer.py targets/libsodium
0x417943 | fe25519_cswap at /home/david.mateos/Desktop/imdea/pandora_fuzzing_dev/revizor/targets/libsodium-1.0.18/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h:168
0x417946 | fe25519_cswap at /home/david.mateos/Desktop/imdea/pandora_fuzzing_dev/revizor/targets/libsodium-1.0.18/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h:169
0x417949 | fe25519_cswap at /home/david.mateos/Desktop/imdea/pandora_fuzzing_dev/revizor/targets/libsodium-1.0.18/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h:166
0x41794c | fe25519_cswap at /home/david.mateos/Desktop/imdea/pandora_fuzzing_dev/revizor/targets/libsodium-1.0.18/src/libsodium/./include/sodium/private/ed25519_ref10_fe_51.h:170
```

## postprocessor.py
Explained [here](../analysis/README.md#post-processing-violations).

## run_campaign.py
This is a simple script that launches several experiments. For each experiment, it writes its configuration file to disk and starts revizor. Revizor is started using `nohup` in order to launch it as a background process, and redirecting its output to a file. The list of experiments is a list of tuples of the form (algorithm, library, leakage model) which can be easily tweaked.