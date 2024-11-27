#!/usr/bin/env bash

function usage() {
  echo "Usage:" >&2
  echo "       $0 CPU_CORES" >&2
  echo ""
  echo "Description: runs LMTEST with all predictors, libraries, and tracers" >&2
  echo "             in parallel by specifying the number of cores on your processor" >&2
  echo ""
  exit 1
}

if [[ $# -ne 1 ]]; then
	usage
elif [[ $1 != +([0-9]) ]]; then
  	usage
fi

# dump all functions in one go
cd src/
python3 -u - <<'pyEOF'
import config, os
for lib, fns in config.FUNCTIONS.items():
	print(lib)
	for alg in fns:
		print(" ",alg)
		dump = os.path.isfile("../violations_db/"+alg+"-"+lib+"/dumps/elf_info.yaml")
		if alg.find('all') == -1 and dump == False: 
			os.system("cd .. && "+"./src/dumper.py "+lib+" "+alg)
pyEOF
cd ..

predictor=(None V1 StraightLine V4Sized RSBDropOldest RSBCircular)
lib=(libsodium cryptlib nettle rust jade)
algo=(salsa stream_xor ed25519 sha512 poly1305 hmac x25519 aes_cbc)
tracers=(constant-time silent-store:ss silent-store:ssi silent-store:ssi0 register-file-compression:rfc register-file-compression:rfc0 narrow-register-file-compression computation-simplification:cs computation-simplification:cst narrow-computation-simplification operand-packing computation-reuse:cr computation-reuse:cra cache-compression:cc-fpc cache-compression:cc-bdi prefetcher:pf-nl prefetcher:pf-stream prefetcher:pf-m1)
parallel --jobs $1 ./run.sh -p {1} {2} {3} -t {4} ::: ${predictor[@]} ::: ${lib[@]} ::: ${algo[@]} ::: ${tracers[@]} &
