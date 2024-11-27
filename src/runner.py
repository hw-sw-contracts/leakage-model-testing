#!/usr/bin/env python3
import sys
import time
import os
from datetime import datetime
from pathlib import Path
from model import get_tracer
from fuzzer import Fuzzer
from config import CONF, TRACERS, get_function, FUNCTIONS
from argparse import ArgumentParser
from service import STAT, LOGGER
from tracers.tracing import BaseTracer

results_dir = 'res/'

def assign_input_type(type_of_input):
    if type_of_input == "constant":
        return "const_"
    elif type_of_input == "random":
        return "rand_"    
    else: 
        return ""

def empty_file(file_name):
    f = open(file_name, "w")
    f.write("")
    f.close()

def append_header_to_file(file_name, library, tracers):
    models = ""
    for tracer, options in tracers.items():
        for leakage_name, option in options:
            models += leakage_name + ", "
    f = open(file_name, "a")
    f.write(library+", "+models+"\n")
    f.close()

def append_to_file(file_name, txt):
    f = open(file_name, "a")
    f.write(txt)
    f.close()

# everything on one line for file_name
def do(type_of_run, type_of_input, algorithm, library, tracers, num_rounds, timeout, base_work_dir, predictors, file_name):
    CONF.algorithm = algorithm
    CONF.library = library
    print(f"[{algorithm} {library}]")
    if predictors:
        print("predictors = ",predictors)
        if "V4SizedPredictor" in predictors:
            CONF.speculation_window = 40
            CONF.nesting_window = 10
    binary = "targets/" + CONF.library
    function = get_function(CONF.algorithm, CONF.library)
    fuzzer = Fuzzer(None, binary, function, predictors)
    append_to_file(file_name, algorithm+", ")
    for tracer, options in tracers.items():
        CONF.tracer = tracer
        for leakage_name, option in options:
            CONF.leakage_name = leakage_name
            CONF.tracer_options = option
            fuzzer.model.tracer = get_tracer()
            if isinstance(fuzzer.model.tracer, BaseTracer):
                pred_str = predictors[0] if predictors else ""
                print(leakage_name, CONF.tracer, fuzzer.model.tracer.__class__.__name__, pred_str, library, algorithm, end=":\n")
            else:
                print(leakage_name, CONF.tracer, CONF.tracer_options, end=":\n")
            STAT.violations = 0

            timestamp = datetime.today().strftime('%Y-%m-%d_%H.%M.%S')
            if type_of_run=="save-violations" or type_of_run=="save-all":
                work_dir = Path(f"{base_work_dir}/{CONF.algorithm}-{CONF.library}/{timestamp}_{leakage_name}")
                work_dir.mkdir(exist_ok=True, parents=True)
                fuzzer.work_dir = work_dir
            num_inputs = 2
            if type_of_input != "random":
                #constant input round
                constant_time_start = time.time()
                duration, timed_out = fuzzer.start_constant(
                    num_inputs=num_inputs,
                    timeout=timeout,
                    save_trace=(type_of_run=="save-violations" or type_of_run=="save-all"),
                    progress_every=1
                )
                constant_time_end = time.time()
                if timed_out:
                    append_to_file(file_name, "T in "+str(duration)+", ")
                    print(f"  timed out\n")
                    continue
                if duration is not None:
                    print(f"  {STAT.violations} violations saved\n")
                    if STAT.violations > 0 and type_of_input == "all":
                        append_to_file(file_name, str(STAT.violations)+" in "+str(duration)+", ")
                        # skip random testing if violation is found using contant test
                        continue
                    if type_of_input == "constant":
                        append_to_file(file_name, str(STAT.violations)+" in "+str(duration)+", ")
                    
            if type_of_input == "constant":
                continue
            
            #random input round
            save_input_to_file = (not predictors and (type_of_input=="all" or type_of_run=="save-input" or type_of_run=="save-all"))
            time_start = time.time()
            duration, timed_out = fuzzer.start(
                num_rounds=num_rounds,
                num_inputs=num_inputs,
                timeout=timeout,
                leakage_info=[library+" "+algorithm+" "+leakage_name, algorithm+"_placeholder"] if save_input_to_file else [],
                save_trace=(type_of_run=="save-violations" or type_of_run=="save-all"),
                progress_every=1
            )
            time_end = time.time()
            if timed_out:
                append_to_file(file_name, "T in "+str(duration)+", ")
                print(f"  timed out\n")
                continue
            append_to_file(file_name, str(STAT.violations)+" in "+str(duration)+", ")
            print(f"  {STAT.violations} violation found\n")

    append_to_file(file_name, "\n")

def main():
    parser = ArgumentParser()
    parser.add_argument(
        "type_of_run",
        choices=["check-violations", "save-violations", "save-input", "save-all"]
    )
    parser.add_argument(
        "type_of_input",
        choices=["random", "constant", "all"],
        default="all"
    )
    parser.add_argument(
        "algorithm",
        type=str,
        help="Algorithm fuzzed",
    )
    parser.add_argument(
        "library",
        type=str,
        help="Library fuzzed",
    )
    parser.add_argument(
        "tracer",
        type=str,
        nargs='?',
    )
    parser.add_argument(
        "-n", "--num-rounds",
        type=int,
        default=100,
        help="Number of rounds.",
    )
    parser.add_argument(
        "-c", "--config",
        type=str,
        required=False
    )
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=14400,
        help="Run fuzzing with a time limit [seconds]. No timeout when set to 0."
    )
    parser.add_argument(
        "-w", "--working-directory",
        type=str,
        default="violations_db",
    )
    parser.add_argument(
        "-p", "--predictor",
        type=str,
        nargs='+',
    )
    
    args = parser.parse_args()
    CONF.logging_modes = []
    if args.config:
        CONF.load(args.config)
    
    LOGGER.set_logging_modes()
    if not os.path.exists(results_dir):
        os.makedirs(results_dir)
    # used for run_all script
    if args.predictor is not None:
        args.predictor = None if "NonePredictor" in args.predictor else args.predictor
    # create file name
    input_type = assign_input_type(args.type_of_input)
    filename = results_dir + input_type + args.library + '_' + args.algorithm
    # specify predictors
    if args.predictor:
        filename += ''.join('_' + pred for pred in args.predictor)
    # specify tracer
    tracers = TRACERS
    if args.tracer:
        filename += '_' + args.tracer.replace(':', '_')
        leakage = None
        tracer = args.tracer
        if ':' in args.tracer:
            tracer, leakage = tracer.split(':')            
        tracers = {tracer: TRACERS[tracer]}
        if leakage:
            tracers[tracer] = [things for things in TRACERS[tracer] if things[0] == leakage]
    # write file
    filename += "_results.csv"
    empty_file(filename)
    append_header_to_file(filename, args.library, tracers)
    # determine run type
    if args.algorithm == "all":
        for alg in FUNCTIONS[args.library]:
            if alg.find('all') == -1:
                do(args.type_of_run, args.type_of_input, alg, args.library, tracers, args.num_rounds, args.timeout, args.working_directory, args.predictor, filename)
    else:
        do(args.type_of_run, args.type_of_input, args.algorithm, args.library, tracers, args.num_rounds, args.timeout, args.working_directory, args.predictor, filename)

if __name__ == "__main__":
    main()
