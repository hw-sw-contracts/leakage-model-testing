# Leakage models
- **Silent stores:** Produces an observation whenever a value is written to memory, and if the value already resides in that memory location, the write operation will be dropped. [paper](https://homes.cs.washington.edu/~dkohlbre/papers/pandora_isca2021.pdf)
	- **SS:** on all memory or only on initialized memory
	- **SSI:** only on initialized memory
	- **SSI0:** only on zero-initialized memory

- **Register File Compression:** Produces an observation whenever a value is written to a register and checks if another register with the same value exists. Logical registers with the same value could be mapped to the same physical register. [paper](https://homes.cs.washington.edu/~dkohlbre/papers/pandora_isca2021.pdf)
	- **RFC:** checks every value
	- **RFC0:** only checks the value 0

- **Narrow Register File Compression:** Produces an observation whenever a narrow value (16 bits or less) is written to a register and checks if there is another register with a narrow value. approximation of [paper](https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.78.9694&rep=rep1&type=pdf)

- **Computation Simplification:** Tracked multiplication, division, and, or, shifts and rotations instructions operating on the the values 0 or 1. Determines whether the results of an operation could be obtained by returning one of the operands. [paper](https://www.ece.uvic.ca/~amiralib/publications/hppac1.pdf)
	- **CS:** checks semi-trivial operations i.e. add, shift, sub, mul, div, and, or, and xor
	- **CST:** checks trivial operations i.e. mul, or, div, and shift

- **Narrow Computation Simplification:** Produces an observation whenever a multiplication instruction with narrow operands (32 bits or less) is executed. suggested by Peter

- **Operand Packing:** Produces an observation whenever an instruction with narrow operands (16 bits or less) is executed and checks for another instruction with the same opcode with narrow operands executed less than X instructions ago. X is the default window size with a value of 200. Additions, subtractions, and, or, xor, not, and shifts instructions are tracked. Check if multiple in-flight instructions can be compressed into a single instruction. [paper](https://mrmgroup.cs.princeton.edu/papers/hpca99.pdf) (section 5)

- **Computation Reuse:** Produces an observation whenever a computation is performed more than once. Simulates a hardware memoization table with a default size of 500, which contains entries for recently cached arithmetic instructions. [paper](https://people.eecs.berkeley.edu/~kubitron/courses/cs252-F03/handouts/papers/p194-sodani.pdf) (section 3.1)
	- **CR:** only checks for the reuse of arithmetic computations semi-trivial operations
	- **CRA:** checks for the reuse of both arithmetic and address calculation operations. ie. mul, or, div, and shift.

- **Cacheline Compression:** Increasing the amount of data available in the cache by compressing cachelines. 
	- **CC-FPC:** Frequence Pattern Compression compresses individual cache lines by storing common word patterns on a word-by-word basis. [paper](https://research.cs.wisc.edu/multifacet/papers/tr1500_frequent_pattern_compression.pdf) 
	- **CC-BDI:**: Base-Delta-Immidiate Compression compresses values within narrow ranges [paper](https://dl.acm.org/doi/10.1145/2370816.2370870) 

- **Prefetching:** Checks for memory access patterns to prefetch memory blocks into cache before instructions request the blocks. 
	- **PF-NL:** Next Line Prefetching prefetches the next memory block upon any load operation [paper](https://doi.org/10.1109/SP46214.2022.9833570)
	- **PF-STREAM:** detects whether the program is accessing addresses at a regular stride and prefetches further memory blocks along the stride [paper](https://www.cse.iitk.ac.in/users/biswap/streamer.pdf)
	- **PF-M1:** detects pointer chasing using an Array-of-Pointers that recognizes reads and dereferences over an array of pointers [paper](https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=9833570)

# Execution models

- **Conditional Speculation (PHT):** Simulates the branch predictor present in modern processors. This predictor model will always mispredict upon any conditional branch instruction during speculative execution. 

- **Straight-line Speculation (SLS):** This model will always mispredict upon any jump micro-operations and speculate for a fixed number of instruction. Simulates straight-line speculation implemented in some AMD cores.

- **Store bypass speculation (STL):** Upon any memory access operation the store micro-operation will be speculatively ignored for a fixed number of instructions.

- **Return Address Speculation Circular (RSBCircular):** Speculation over return instructions. Employ a return stack buffer to determine the speculative target. During over-flow or under-flow of the return stack buffer the entry wrap around the buffer.

- **Return Address Speculation Drop Oldest (RSBDropOldest):** Speculation over return instructions. Employ a return stack buffer to determine the speculative target. During over-flow of the return stack buffer the entry will be dropped and the rollback operation will be performed during under-flow.