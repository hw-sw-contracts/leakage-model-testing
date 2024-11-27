"""
File: Fuzzing Orchestration

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import shutil
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Tuple
from copy import copy

from interfaces import Input, EquivalenceClass, InputGenerator, Model, InputID, Trace, Analyser, Measurement
from input_generator import get_input_generator
from model import get_model, State
from analyser import get_analyser
from service import STAT, LOGGER, MASK_64BIT
from config import CONF
import time
import signal

Multiprimer = Dict[Input, List[Input]]

def sigint_handler(sig, frame):
    import sys
    raise RuntimeError("^C")
signal.signal(signal.SIGINT, sigint_handler)

class Fuzzer:
    work_dir: str
    binary_path: str
    input_gen: InputGenerator
    model: Model
    analyser: Analyser

    def __init__(self, work_dir: str, binary_path: str, function_name: str, predictors: list[str]):
        self.work_dir = work_dir
        self.binary_path = binary_path
        self.model: Model = get_model(binary_path, function_name, predictors)
        self.input_gen: InputGenerator = get_input_generator(self.model.STACK, self.model.STACK_SIZE)
        self.analyser: Analyser = get_analyser()

    def start(self, num_rounds: int, num_inputs: int, timeout: int, leakage_info: [str], save_trace: bool = False, progress_every: int = 0) -> Tuple[float, bool]:
        start_time = datetime.today()
        LOGGER.fuzzer_start(num_rounds*num_inputs, start_time)
        next_progress = progress_every
        timed_out = False
        for i in range(num_rounds):
            LOGGER.fuzzer_start_round(i)
            violation, params, timed_out = self._fuzzing_round(num_inputs)
            if timed_out: 
                break
            if violation:
                LOGGER.fuzzer_report_violations(violation, self.model)
                if save_trace:
                    self._store_violation(violation)
                if leakage_info:
                    self._save_violation_input(params, leakage_info)
                STAT.violations += 1
                break
            now = datetime.today()
            elapsed = (now - start_time).total_seconds()
            if timeout and elapsed > timeout:
                LOGGER.fuzzer_timeout()
                break
            if progress_every >= 0 and elapsed >= next_progress:
                next_progress += progress_every
            
        now = datetime.today()
        elapsed = (now - start_time).total_seconds()
        print(f"  Completed {i+1:4} rounds after {elapsed:4.2f} seconds...")
        LOGGER.fuzzer_finish()
        return round(elapsed,2), timed_out

    def start_constant(self, num_inputs: int, timeout: int, save_trace: bool = False, progress_every: int = 0) -> Tuple[float, bool]:
        num_rounds = 0
        # check if an algorithm contains test vectors
        num_rounds = len(self.input_gen.VECTORS)
        if not num_rounds:
            return None
        start_time = datetime.today()
        LOGGER.fuzzer_start(num_rounds*num_inputs, start_time)
        next_progress = progress_every
        timed_out = False
        for i in range(num_rounds):
            LOGGER.fuzzer_start_round(i)
            violation, timed_out = self._fuzzing_constant_round(num_inputs, i)
            if timed_out:
                break
            if violation:
                LOGGER.fuzzer_report_violations(violation, self.model)
                if save_trace:
                    self._store_violation(violation)
                STAT.violations += 1
                break
            now = datetime.today()
            elapsed = (now - start_time).total_seconds()
            if timeout and elapsed > timeout:
                LOGGER.fuzzer_timeout()
                break
            if progress_every >= 0 and elapsed >= next_progress:
                next_progress += progress_every
            
        now = datetime.today()
        elapsed = (now - start_time).total_seconds()
        print(f"  Completed {i+1:4} constant rounds after {elapsed:4.2f} seconds...")
        LOGGER.fuzzer_finish()
        return round(elapsed,2), timed_out

    def _fuzzing_round(self, num_inputs: int) -> tuple[EquivalenceClass, Input, bool]:
        num_inputs_gen = num_inputs
        inputs: List[Input] = self.input_gen.generate(num_inputs_gen)
        traces: List[Trace] = []
        params_byte = inputs.pop()
        params = inputs.pop()
        timed_out = False
        for i in range(len(inputs)):
            trace, inst_count, timed_out = self.model.trace_test_case(inputs[i])
            if timed_out:
                return (None, params_byte, timed_out)
            self._update_stat_check_results(traces, trace, inst_count, inputs[i])
                
        pubs = [input_.public_observation() for input_ in inputs]
        violations = self.analyser.filter_violations(inputs, pubs, traces, stats=True)
        return (violations.pop(), params_byte, timed_out) if violations else (None, None, timed_out)

    def _fuzzing_constant_round(self, num_inputs: int, index: int) -> tuple[EquivalenceClass, bool]:
        num_inputs_gen = num_inputs
        inputs: List[Input] = self.input_gen.generate_constant(num_inputs_gen, index)
        traces: List[Trace] = []
        timed_out = False
        for i in range(len(inputs)):
            trace, inst_count, timed_out = self.model.trace_test_case(inputs[i])
            if timed_out:
                return (None, timed_out)
            self._update_stat_check_results(traces, trace, inst_count, inputs[i])

        pubs = [input_.public_observation() for input_ in inputs]
        violations = self.analyser.filter_violations(inputs, pubs, traces, stats=True)
        return (violations.pop(), timed_out) if violations else (None, timed_out)

    def _update_stat_check_results(self, traces: List[Input], trace: Trace, inst_count: int, input_i: Input):
        traces.append(trace)
        STAT.test_cases += 1
        STAT.instruction_count += inst_count
        if CONF.check_results:
            self.input_gen.check_result(input_i, self.model.get_stack())

    def _save_input(self, path: Path, input_name: str, input_: Input, trace: Trace = None):
        path_stack = path.joinpath(f"{input_name}_stack")
        path_regs = path.joinpath(f"{input_name}_regs")
        path_trace = path.joinpath(f"{input_name}_trace")
        with path_stack.open("wb") as f:
            f.write(input_.stack)
        with path_regs.open("w") as f:
            f.write(str(input_.regs))
        if trace is not None:
            with path_trace.open("w") as f:
                f.writelines(f"{obs}\n" for obs in trace.trace)

    def _save_test(self, entry: str, leakage_info: [str]):
        search_text = leakage_info[1]
        with open(r'src/saved_test.py', 'r') as file:
            data = file.read() 
            data = data.replace(search_text, entry)
        
        with open(r'src/saved_test.py', 'w') as file:
            file.write(data)

    def _save_violation_input(self, input_bytes: Input, leakage_info: [str]):
        string = "		{\n"
        for param, value in input_bytes.items():
            if param.find('len') != -1:
                continue
            string += "			\""+str(param) +"\" : ["
            for byte in value:
                string += " " + str(hex(byte)) + "," 
            string += "],\n"
        string += "		},"
        self._save_test("#"+leakage_info[0]+"\n"+string+"\n        #"+leakage_info[1],leakage_info)

    def _store_violation(self, violation: EquivalenceClass):
        if not self.work_dir:
            LOGGER.warn_violation_not_saved()
            return

        timestamp = datetime.today().strftime('%Y-%m-%d_%H.%M.%S')
        pub_hash = violation.pub.deterministic_hash() & MASK_64BIT
        violation_dir = Path(self.work_dir).joinpath(f"{STAT.violations + 1:04}_{timestamp}_{pub_hash:#x}")
        if violation_dir.exists():
            LOGGER.warning("fuzzer", f"violation not saved because path '{violation_dir}' already exists")
            return
        violation_dir.mkdir()

        # Save a representative of each group of inputs with different traces
        for input_ids in violation.trace_map.values():
            input_id = input_ids[0]
            m: Measurement = violation.measurements[input_id]
            self._save_input(violation_dir, str(input_id), m.input_, m.trace)
        # config_path = violation_dir.joinpath("config.yaml")
        # CONF.save(config_path)
