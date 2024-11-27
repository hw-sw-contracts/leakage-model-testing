# LMTEST
LMTEST is a testing framework for exploring the security impact of future microarchitectural optimizations by automatically detecting leaks in cryptographic implementations. For this, LMTEST is parametric in a given [leakage model](src/tracers/) that captures, at the program level, what information might be leaked by the  proposed microarchitectural optimization. LMTEST supports leakage models formalized in the LMSPEC language, an expressive domain-specific language supporting the specification of leakage clauses (capturing which information is leaked) and prediction clauses (which specifies the prediction mechanism supported by the microarchitecture and what their effects are). 

For more details, see [paper](https://arxiv.org/abs/2402.00641). 

**Acknowledgments:** LMTEST is based on part of the [Revizor](https://github.com/microsoft/sca-fuzzer) testing tool codebase.

## How to setup LMTEST
### 1. Check System Requirements
**Processor**: LMTEST supports all Intel and AMD x86-64 CPUs (tests were performed on Intel Xeon Gold 6132 and Intel i7 10750H).    
**Memory**: 16 GB RAM or more is recommended, as predictors are relatively memory intensive.      
**Storage**: 10 GB available space.   
**Virtualization**: supports hardware installed OS and virtual machine.        

### 2. Install the following dependencies: 
* gcc version 11.4.0
* clang 14.0.0-1ubuntu1.1
* Python3 >= v3.9.2
* wget 1.21.2
* gmp 6.2.1
* cargo 1.73.0-nightly
* zstd v1.4.8 (for extracting libgmp static library)
* [jasminc](https://github.com/jasmin-lang/jasmin/wiki/Installation-instructions) (Jasmin Compiler 2023.06.0)
### 3. Install the following Python modules: 
* recordclass 0.19.1
* pyyaml 5.4.1
* unicorn 2.0.1.post1
* pyelftools 0.29
* capstone 5.0.0.post1
* pexpect 4.8.0
* ruamel.yaml 0.17.32
* bitstring 4.0.2
* hy 0.27.0
* hyrule 0.4.0
* iced-x86 1.19.0
* rich 13.4.2
### 4. Navigate to [targets/](targets/) and download the required libraries and build all test programs by running:
```bash
$ ./build.sh
```

### 5. For more information on how to use LMTEST, run:
```bash
$ ./run.sh -h
```
## Commandline interface
LMTEST uses two driver scripts found in the [revizor/](./) directory: `run.sh` and `run_all.sh` to execute the testing framework. 
### run.sh
#### Usage
`./run.sh [OPTIONS] [PREDICTORS] library function [INPUT_TYPE] [TRACER]` 
#### Description
Runs LMTEST using a given PREDICTOR (prediction clause), library, function, and TRACER (leakage clause), respectively.
#### OPTIONS
```bash
	-h   show help and exit
 	-l   list libraries/functions and exit
	-L   list by functions and exit
 	-n TEST_CASES set number of test cases used for each TRACER (default: 100)
```
#### PREDICTORS
```bash
	--list-predictors and exit
 	-p PRED use given predictor; can be specified multiple times to use multiple prediction clauses at the same time
```
#### INPUT_TYPE (default: all)
```bash
 	-c   only use constant predefined inputs for testing
 	-r   only use randomized inputs for testing
 ```
#### TRACER (default: all)
```bash
	--list-tracers and exit
 	-t TRAC use given tracer
 ```
#### EXAMPLE 1:
```bash
./run.sh -n 20 -p V1 libsodium x25519 -r
```
Runs LMTEST with 20 test cases per **TRACER** using the V1 **PREDICTOR** testing x25519 **function** in the libsodium **library** via random input. Since a **TRACER** is not specified LMTEST will use each **TRACER** in `src/tracers`.

#### EXAMPLE 2:
```bash
./run.sh nettle salsa -t silent-store:ss
```
Runs LMTEST for the default 100 test cases per **TRACER**. The predictor will be disabled since none is specified. LMTEST will test the `salsa` **function** (implementing the salsa20 authenticated encryption algorithm) in the nettle **library** via both predefined and random input since **INPUT_TYPE** is not specified. The silent-store:ss **TRACER** will be used.  

### run_all.sh
#### Usage
`./run_all.sh CPU_CORES` 
#### Description
Runs LMTEST with all PREDICTOR (execution model), library, function, and TRACER (leakage model). Execution is done in parallel by specifying CPU_CORES to denote maximum core usage. 
#### EXAMPLE:
```bash
./run_all.sh 8
```
runs all test cases in parallel for **PREDICTOR** \* **library** \* **function** \* **TRACER** utilizing a maximum of **8** cores 




# Artifact evaluation

Here we describe how to evaluate and reproduce the claims from the evaluation section (Section 6) of our CCS 2024 paper. 
The evaluation section studies three research questions (RQ1--RQ3). Next, we discuss how to evaluate them. Note that RQ2 is the only research question that requires computation (to re-run the testing campaign). In contrast, RQ1 and RQ3 can be evaluated by inspecting artifacts in the repository.

### RQ1: Does LMSPEC provide an expressive and concise framework for specifying leakage models?

The paper claims that LMSPEC indeed provides an expressive and concise framework for specifying leakage models. To back up this claim, the authors implemented 18 leakage clauses and 6 prediction clauses, which combined result in 108 leakage models.

All leakage and prediction clauses are available in `src/tracers/leakage_models.hy` and `src/tracers/execution_models.hy`. Further information on the supported leakage and speculation clauses is available in `src/tracers/REAMDE.md`.

### RQ2: Are real-world cryptographic libraries secure under the different leakage models and can LMTEST detect leaks in them?

The paper claims that (1) several cryptographic algorithms are leaky under the studied leakage models, and (2) that LMTEST can help in detecting these leaks. These claims are backed up by the testing campaign whose results are reported in Table 1 in Section 6.

To reproduce the results of the testing campaign, one can run the `run_all.sh` script and inspect the results of the campaign.

**NOTE:** Running the entire testing campaign can take multiple hours (>12h on some systems). 

To reproduce a single entry in the table, one can use the `run.sh` script. In particular, for testing a function for a given library under specific leakage  and prediction clauses one can run (i.e., a single entry in Table 1): `./run.sh LIBRARY FUNCTION -t LEAKAGE_CLAUSE -p PREDICTION_CLAUSE`.

### RQ3: Can the leaks be exploited?

The paper claims that some of the discovered leaks are security relevant. In particular, we analyzed leaks in the libsodium implementation of the X25519 algorithm and identified leaks that can be used to recover the used secret key directly from the leakage trace. 

Beyond the short description in section 6.3, a more exhaustive description of the identified leaks is given in `analysis/x25519-libsodium.md`. This description contains (1) the leaky code-lines and (2) a description of how to recover the secret key from the trace.

# Extending LMTEST

Below we describe how to extend LMTEST with (1) new leakage and prediction clauses, and (2) new testing targets.

## Adding a new leakage or prediction clause

Adding a new leakage clause to LMTEST can be done by simply adding a new clause to `src/tracers/leakage_models.hy`. The leakage clause can be specified, following LMSPEC's syntax, as a `(defleakage ...)` construct. LMTEST will automatically load the leakage model and make it available through the `-t` command line option.


Similarly, adding a new prediction clause to LMTEST can be done by simply adding a new clause to `src/tracers/execution_models.hy`. The prediction clause can be specified, following LMSPEC's syntax, as a `(defpredictor ...)` construct. LMTEST will automatically load the leakage model and make it available through the `-p` command line option.

For more details on LMSPEC, see the [paper](https://arxiv.org/abs/2402.00641).

## Adding cryptographic functions to LMTEST 

Below, we describe how one can use LMTEST to test a new cryptographic implementation (beyond those analyzed in the paper).

### 1. Download and build static library in [targets/build.sh](targets/build.sh)
```bash
# Example
function build_static_library(){
	if [[ library path does not exist]]; then
		# download library from source	
	fi
	if [[ static library file does not exist]]; then
		# build library	
	fi
}
```

### 2. Create a test program in C and compile in [targets/build.sh](targets/build.sh)

```c
// Example
#include "library_header_files"

void call_function() {
  unsigned char out[DATA_SIZE] = {0};
  unsigned char in[DATA_SIZE] = {0};
  function(out, in, 0);
}

int main(){
 call_crypto_function();
 return 0;
}

```

```bash
# Example
function build_static_library(){
	# compile test program
}
```
### 2. Add library and function name to [src/config.py](src/config.py)
```bash
# Check if the library and function were successfully added
$  ./run.sh -l
```
### 3. Create an input generator for the function in [src/input_generator.py](src/input_generator.py)
```python
# Example
class FunctionInputGenerator(RandomInputGenerator):
    # Optional: include constant input 
    VECTORS = ZERO_VECTORS["function"] + TEST_VECTORS["function"]

    def get_signature(self):
        return {
		#include function parameters with data type
        }

    # Optional
    def check_result(self, input_: Input, stack_result: bytes) -> None:
	# add result verification here
        if result != out:
            LOGGER.emulation_error(out, result)
```
### 4. Test function using included [leakage models](src/tracers/)
```bash
# use default settings
$  ./run.sh library function
```

