#!/usr/bin/env python3
"""
File: Command Line Interface

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""

import os
import hashlib
from typing import Dict
from argparse import ArgumentParser
from fuzzer import Fuzzer
from config import CONF, get_function
from service import LOGGER

def md5(path):
    with open(path, 'rb') as f:
        return hashlib.md5(f.read()).hexdigest()

def main():
    parser = ArgumentParser(description='', add_help=False)
    parser.add_argument(
        "-c", "--config",
        type=str,
        required=False
    )
    parser.add_argument(
        "-n", "--num-rounds",
        type=int,
        default=5,
        help="Number of rounds.",
    )
    parser.add_argument(
        "-i", "--num-inputs",
        type=int,
        default=100,
        help="Number of inputs per round.",
    )
    parser.add_argument(
        '-w', '--working-directory',
        type=str,
        default='',
    )
    parser.add_argument(
        '--timeout',
        type=int,
        default=0,
        help="Run fuzzing with a time limit [seconds]. No timeout when set to zero."
    )
    parser.add_argument(
        '--nonstop',
        action='store_true',
        help="Don't stop after detecting an unexpected result"
    )
    parser.add_argument(
        '--cpu',
        type=int,
        default=0,
        help="The cpu this script will run on."
    )

    args = parser.parse_args()

    # Update configuration
    if args.config:
        CONF.load(args.config)
    LOGGER.set_logging_modes()

    # Make sure we're ready for fuzzing
    if args.working_directory and not os.path.isdir(args.working_directory):
        raise SystemExit("The working directory does not exist")

    # pin to a single cpu
    LOGGER.info("cli", f"pinning to cpu {args.cpu}")
    os.sched_setaffinity(0, {args.cpu})

    if CONF.library not in ("nacl", "libsodium", "openssl"):
        raise Exception(f"Unknown library {CONF.library}")
    binary = "targets/" + CONF.library

    function = get_function(CONF.algorithm, CONF.library)

    fuzzer = Fuzzer(args.working_directory, binary, function)
    fuzzer.start(
        args.num_rounds,
        args.num_inputs,
        args.timeout,
        args.nonstop,
    )



if __name__ == '__main__':
    main()
