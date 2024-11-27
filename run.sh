#!/usr/bin/env bash
set -eu

function usage() {
  echo "Usage:" >&2
  echo "       $0 [OPTIONS] [PREDICTOR] library function [INPUT_TYPE] [TRACER]" >&2
  echo ""
  echo "Description: runs LMTEST given a predictor model, library, function," >&2
  echo "             and leakage model then writes the results to ./res" >&2
  echo ""
  echo "OPTIONS" >&2
  echo "  -h     show help and exit" >&2
  echo "  -l     list libraries/functions and exit" >&2
  echo "  -L     list by functions and exit" >&2
  echo "  -n TEST_CASES set number of test cases for each TRACER (default: 100)" >&2
  echo ""
  echo "PREDICTOR (default: none)" >&2
  echo "  --list-predictors and exit" >&2
  echo "  -p PRED  use given predictor; can be specified multiple times" >&2
  echo ""
  echo "INPUT_TYPE (default: all)" >&2
  echo "  -c     only use constant predefined input for testing" >&2
  echo "  -r     only use random input for testing" >&2
  echo ""
  echo "TRACER (default: all)" >&2
  echo "  --list-tracers and exit" >&2
  echo "  -t TRAC  use given tracer" >&2
  echo ""  
  exit 1
}

if [[ $# -eq 0 ]]; then
  usage
fi

tracer=""
input="all"
args=$(getopt -l "list-predictors,list-tracers" -- 'hlLrcp:n:t:' "$@")
predictors=()
numrounds=100 
eval set -- "$args"

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h )
      usage;;
    -l )
      cd src
      python3 -u - "$@" <<'pyEOF'
import config, sys, os
args = sys.argv[sys.argv.index('--')+1:]
if args and args[0] in config.FUNCTIONS:
    lib = args[0]
    print(lib, *config.FUNCTIONS[lib], sep='\n    ')
else:
    for k, vs in config.FUNCTIONS.items():
        print(k, *vs, sep='\n    ')
pyEOF
      exit 0;;
    -L )
      cd src
      python3 -u - <<'pyEOF'
import config
from collections import defaultdict as ddict
fns = ddict(list)
for k, vs in config.FUNCTIONS.items():
    for v in vs:
      fns[v].append(k)
for v, ks in sorted(fns.items()):
    print(v, *sorted(ks), sep='\n    ')
pyEOF
      exit 0;;
    --list-tracers )
      cd src/
      python3 -u - "$@" <<'pyEOF'
import config, sys, os
for tracer, types in config.TRACERS.items():
  print("  ",tracer)
  for type in types:
    print("      ",tracer+":"+type[0])
pyEOF
      cd ..
      exit 0;;
    --list-predictors )
      cd src
      # force hy to recompile models
      rm -rf tracers/__pycache__
      python3 -u - <<'pyEOF'
import hy
from tracers import tracing, execution_models
for name, cls in vars(execution_models).items():
    if name == "BasePredictor":
        continue
    if isinstance(cls, type) and issubclass(cls, tracing.BasePredictor):
        print(name.removesuffix("Predictor"))
pyEOF
      exit 0;;
    -p )
      predictors+=("$2Predictor")
      shift 2;;
    -n )
      numrounds=$2
      shift 2;;
    -t )
      tracer=$2
      shift 2;;
    -c )
      input="constant"
      shift;;
    -r )
      input="random"
      shift;;
    -- )
      shift
      if [[ $# -eq 1 ]]; then
        ( usage ) ||:
        $0 -l $1
        exit 1
      elif [[ $# -gt 3 ]]; then
        usage
      fi
      lib=$1
      alg=$2
      break;;
  esac
done

if [[ ${#predictors[@]} -gt 0 ]]; then
  predictors=("-p" "${predictors[@]}")
fi

# dump function binary
if [[ "$2" == *"all"* ]]; then
  cd src/
  python3 -u - "$@" <<'pyEOF'
import config, sys, os
for alg in config.FUNCTIONS[sys.argv[1]]:
  dump = os.path.isfile("../violations_db/"+alg+"-"+sys.argv[1]+"/dumps/elf_info.yaml")
  if alg.find('all') == -1 and dump == False:
    os.system("cd .. && "+"./src/dumper.py "+sys.argv[1]+" "+alg)
pyEOF
  cd ..
elif [[ ! -f violations_db/$alg-$lib/dumps/elf_info.yaml ]]; then
  ./src/dumper.py $lib $alg
fi

# for now, force hy to recompile leakage models every time
rm -rf src/tracers/__pycache__
all_pred="${predictors[@]}"
echo "./src/runner.py check-violations $input -n $numrounds $alg $lib $tracer $all_pred"
./src/runner.py check-violations $input -n $numrounds $alg $lib $tracer "${predictors[@]}"  
