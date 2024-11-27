"""
File: Global classes that provide service to all Revizor modules

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""

from datetime import datetime

from interfaces import EquivalenceClass
from config import CONF
from typing import NoReturn

POW2_64 = pow(2, 64)
MASK_64BIT = pow(2, 64) - 1


class StatisticsCls:
    test_cases = 0
    instruction_count = 0
    eff_classes = 0
    single_entry_classes = 0
    violations = 0

    old_test_cases = 0
    old_instruction_count = 0
    old_time = datetime.today()

    def __str__(self):
        total_clss = self.eff_classes + self.single_entry_classes
        total_clss_perc = 100 * total_clss / self.test_cases if self.test_cases else 0
        effective_clss = 100 * self.eff_classes / self.test_cases if self.test_cases else 0

        s = "\n================================ Statistics ===================================\n"
        s += f"Test Cases: {self.test_cases}\n"
        s += f"Total Cls: {total_clss_perc:.1f}%\n"
        s += f"Effective Cls: {effective_clss:.1f}%\n"
        s += f"Violations: {self.violations}\n"
        return s

    def get_brief(self):
        if self.test_cases == 0:
            return ""
        else:
            cur_time = datetime.today()
            total_clss = self.eff_classes + self.single_entry_classes
            tcps = (self.test_cases - self.old_test_cases) / (cur_time - self.old_time).total_seconds()
            ips = (self.instruction_count - self.old_instruction_count) / (cur_time - self.old_time).total_seconds()
            self.old_test_cases = self.test_cases
            self.old_instruction_count = self.instruction_count
            self.old_time = cur_time
            s = f"AlCl:{100 * total_clss / self.test_cases:.1f}%, "
            s += f"EfCl:{100 * self.eff_classes / self.test_cases:.1f}%, "
            s += f"Tcps:{tcps:.1f}, "
            s += f"Ips:{ips/1000:.1f}k, "
            return s


STAT = StatisticsCls()


class Logger:
    """
    A global object responsible for printing stuff.

    Has the following levels of logging:
    - Error: Critical error. Prints a message and exits
    - Warning: Non-critical error. Always printed, but does not exit
    - Info: Useful info. Printed only if enabled in CONF.logging_modes
    - Debug: Detailed info. Printed if both enabled in CONF.logging_modes and if __debug__ is set.
             Enabled separately for each module.
    - Trace: Same as debug, but for the cases when the amount of printed info is huge
    """

    max_test_cases: int = 0
    msg: str = ""
    line_ending: str = ""
    redraw_mode: bool = True

    # info modes
    info_enabled: bool = False
    stat_enabled: bool = False
    report_violations_enabled: bool = False

    # debugging modes
    fuzzer_debug: bool = False
    fuzzer_trace: bool = False
    model_debug: bool = False
    coverage_debug: bool = False

    def __init__(self) -> None:
        class Unbuffered(object):
            def __init__(self, stream):
                self.stream = stream
            def write(self, data):
                self.stream.write(data)
                self.stream.flush()
            def writelines(self, datas):
                self.stream.writelines(datas)
                self.stream.flush()
            def __getattr__(self, attr):
                return getattr(self.stream, attr)

        import sys
        sys.stdout = Unbuffered(sys.stdout)

    def set_logging_modes(self):
        mode_list = CONF.logging_modes
        if "info" in mode_list:
            self.info_enabled = True
        if "stat" in mode_list:
            self.stat_enabled = True
        if "report_violations" in mode_list:
            self.report_violations_enabled = True
        if "fuzzer_debug" in mode_list:
            self.fuzzer_debug = True
        if "fuzzer_trace" in mode_list:
            self.fuzzer_trace = True
        if "model_debug" in mode_list:
            self.model_debug = True
        if "coverage_debug" in mode_list:
            self.coverage_debug = True

        if not __debug__:
            if self.fuzzer_debug or self.model_debug or self.coverage_debug or self.fuzzer_trace:
                self.warning("", "Debugging mode was not enabled! Remove '-O' from python arguments")

    def error(self, msg) -> NoReturn:
        if self.redraw_mode:
            print("")
        print(f"ERROR: {msg}")
        exit(1)

    def warning(self, src, msg) -> None:
        if self.redraw_mode:
            print("")
        print(f"WARNING: [{src}] {msg}")

    def info(self, src, msg, end="\n") -> None:
        if self.info_enabled:
            if self.redraw_mode:
                print("")
            print(f"INFO: [{src}] {msg}", end=end, flush=True)

    # ==============================================================================================
    # Fuzzer
    def dbg_fuzzer(self, msg) -> None:
        if __debug__:
            if self.fuzzer_debug:
                print(f"DBG: [fuzzer] {msg}")

    def fuzzer_start(self, iterations: int, start_time):
        if self.info_enabled:
            self.max_test_cases = iterations
            self.msg = ""
            self.line_ending = '\n' if CONF.multiline_output else ''
            self.redraw_mode = False if CONF.multiline_output else True
            self.start_time = start_time
        self.info("fuzzer", start_time.strftime(
            f'Starting at %H:%M:%S, fuzzing {CONF.algorithm} on {CONF.library}, '
            f'with optimization {CONF.tracer}, and options {CONF.tracer_options}'
        ))

    def fuzzer_start_round(self, round_id):
        if __debug__ and self.info_enabled and round_id and round_id % 1000 == 0:
            self.dbg_fuzzer(
                f"Current duration: {(datetime.today() - self.start_time).total_seconds()}")

        if self.info_enabled:
            perc = 100 * STAT.test_cases / self.max_test_cases
            msg = f"\rProgress: {STAT.test_cases}|{perc:.1f}%, "
            msg += STAT.get_brief()
            print(msg + "> Normal execution              ", end=self.line_ending, flush=True)
            self.msg = msg

    def fuzzer_priming(self, num_violations: int):
        if self.info_enabled:
            print(
                self.msg + "> Priming:" + str(num_violations) + "           ",
                end=self.line_ending,
                flush=True)

    def fuzzer_nesting_increased(self):
        if self.info_enabled:
            print(
                self.msg + "> Trying max nesting:" + str(CONF.model_max_nesting) + "         ",
                end=self.line_ending,
                flush=True)

    def fuzzer_timeout(self):
        self.info("fuzzer", "\nTimeout expired")

    def fuzzer_finish(self):
        if self.info_enabled:
            now = datetime.today()
            print("")  # new line after the progress bar
            if self.stat_enabled:
                print(STAT)
            print(f"Duration: {(now - self.start_time).total_seconds():.1f}")
            print(datetime.today().strftime('Finished at %H:%M:%S'))

    def print_hash(self, value):
        if value <= pow(2, 64):
            print(f"    {value & MASK_64BIT:#018x}")
        else:
            print(f"    {value & MASK_64BIT:#018x} [ns]\n"
                  f"    {(value >> 64) & MASK_64BIT:#018x} [s]\n")

    def warn_violation_not_saved(self):
        if self.report_violations_enabled:
            LOGGER.warning("fuzzer", "violation not saved because option -w was not specified")

    def fuzzer_report_violations(self, violation: EquivalenceClass, model):
        if not self.report_violations_enabled:
            return

        print("\n\n================================ Violations detected ==========================")
        print("  Input hash:")
        self.print_hash(violation.pub.deterministic_hash())
        print("  Hardware traces:")
        for trace_hash, inputs in violation.trace_map.items():
            if len(inputs) < 4:
                print(f"   Inputs {inputs}:")
            else:
                print(f"   Inputs {inputs[:4]} (+ {len(inputs) - 4} ):")
            self.print_hash(trace_hash)
        print("")

    def emulation_error(self, expected, found):
        print("\n\n================================ Emulation error ==========================")
        print("Results differ in emulation and native execution")
        print(f"\tExpected: {expected.hex()}")
        print(f"\tFound:    {found.hex()}")
        self.error("emulation error")



LOGGER = Logger()


# ==================================================================================================
# Small helper functions
# ==================================================================================================
def bit_count(n):
    count = 0
    while n:
        count += n & 1
        n >>= 1
    return count


class NotSupportedException(Exception):
    pass
