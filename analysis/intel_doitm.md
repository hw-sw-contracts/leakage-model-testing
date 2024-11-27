
## Data Operand Independent Timing Mode
Intel introduces [Data Operand Independent Timing Mode](https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/best-practices/data-operand-independent-timing-isa-guidance.html
) (DOITM). When enabled, latency of *some* instructions does not depend on its operand values (list [here](https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/resources/data-operand-independent-timing-instructions.html)). If not supported by the CPU (those before Ice Lake), it acts as if it were enabled. If disabled, Intel makes no guarantee about any instruction.

DOIT Mode is enabled with a MSR. This means it requires privileged access. There is some active discussion in the linux mailing list ([here](https://lore.kernel.org/linux-arm-kernel/YwgCrqutxmX0W72r@gmail.com/T/)). They are suggesting making it per-thread, which would imply having to save and restore it on context switch. They propose enabling and disabling it using `prctl`, and maybe changing its default value with a sysctl. They don't seem to be sure whether DOITM should be enabled by default.

Even with DOITM enabled, some vector instructions have data-dependent timing due to MXCSR configuration. Intel called this MXCSR Configuration Dependent Timing (MCDT). MXCSR is a register containing control and status bits for floating point registers. Some of its options include Flush-To-Zero and Denormals-Are-Zeros, which [@moyix](https://twitter.com/moyix) talked about ([twitter](https://twitter.com/moyix/status/1565097799380787201) and [blog post](https://moyix.blogspot.com/2022/09/someones-been-messing-with-my-subnormals.html)) and which change the behaviour of the CPU when operating with values very close to 0. Intel introduces a CPUID bit called MCDT_NO. If it's 1, it means the processor doesn't have this MCDT behaviour, and the execution time doesn't depend on its operands when DOITM is enabled. If it's 0, even with DOITM enabled, there may be timing differences depending on the operands and the MXCSR register. Also, processors before Skylake seem to also not be affected despite setting this MCDT_NO bit to 0.

In practice, I tried to use nanobench to measure IMUL instruction on a modern processor with DOITM disabled. I wanted to test if any kind of computation simplification is present in modern Intel CPUs. I tested multiplication by 0 and narrow computation simplification. But it doesn't seem to be any difference in execution time (cycles). The following commands produce the same results:
```
sudo ./nanoBench.sh -asm_init "MOV RAX, 0; MOV RDI, 0x1122334455667788" -asm "IMUL RDI, RAX" -config configs/cfg_TigerLake_common.txt
```
```
sudo ./nanoBench.sh -asm_init "MOV RAX, 0x8877665544332211; MOV RDI, 0x1122334455667788" -asm "IMUL RDI, RAX" -config configs/cfg_TigerLake_common.txt
```
```
sudo ./nanoBench.sh -asm_init "MOV RAX, 0; MOV RDI, 0x1122" -asm "IMUL RDI, RAX" -config configs/cfg_TigerLake_common.txt
```
```
sudo ./nanoBench.sh -asm_init "MOV RAX, 0x2211; MOV RDI, 0x1122" -asm "IMUL RDI, RAX" -config configs/cfg_TigerLake_common.txt
```

It would be nice to find an instruction whose execution time depends on its operands, and then check if it's solved with DOITM enabled.


In order to check for DOIT Mode support:
- support for `IA32_ARCH_CAPABILITIES` MSR: check cpuid(eax=7, ecx=0) EDX[29]
  
  ```
  cpuid -l 7 -s 0 | grep IA32_ARCH_CAPABILITIES
  ```

- support for `IA32_UARCH_MISC_CTL` MSR: check `IA32_ARCH_CAPABILITIES[DOITM]` MSR (`0x10a[12]`)
  
  ```
  sudo rdmsr 0x10a # and check bit 12
  ```
- enable: `IA32_UARCH_MISC_CTL[DOITM]` MSR (`0x1b01[0]`)
  ```
  sudo rdmsr 0x1b01    # should be 0 by default
  sudo wrmsr 0x1b01 1
  ```
