"""
File: Fuzzing Configuration Options

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from typing import List, Optional
from dataclasses import dataclass
import yaml

FUNCTIONS = {
    "libsodium": {
        "ed25519": "crypto_sign_ed25519",
        "hmac": "crypto_auth",
        "poly1305": "crypto_onetimeauth_poly1305",
        "salsa": "salsa20",
        "sha512": "crypto_hash_sha512",
        "stream_xor": "crypto_stream_xor",
        "x25519": "x25519_mul",
        "all":  ""
    },
    "cryptlib": {
        "aes_cbc": "aes_enc",
        "sha512": "sha512",
        "all":  ""
    },
    "nettle": {
        "aes_cbc": "aes_enc",
        "ed25519": "crypto_sign_ed25519",
        "hmac": "hmac",
        "salsa": "salsa20",
        "sha512": "sha512",
        "x25519": "x25519_mul",
        "all":  ""
    },
    "rust": {
        "poly1305": "poly1305",
        "salsa": "salsa20",
        "sha512": "sha512_rust",
        "stream_xor": "crypto_stream_xor",
        "x25519": "x25519_mul",
        "all":  ""
    },
    "jade": {
        "poly1305": "crypto_onetimeauth_poly1305",
        "salsa": "salsa20",
        "sha512": "sha512",
        "stream_xor": "crypto_stream_xor",
        "x25519": "x25519_mul",
        "all":  ""
    },
}

def get_function(algorithm, library):
    assert library in FUNCTIONS, f"unknown library {library!r}; choose from {tuple(FUNCTIONS.keys())}"
    try:
        function = FUNCTIONS[library][algorithm]
    except KeyError:
        raise KeyError(f"unknown algorithm for {library!r}; choose from {tuple(FUNCTIONS[library].keys())}") from None
    return function

def get_algorithm(function, library):
    try:
        return next(k for k, v in FUNCTIONS[library].items() if v == function)
    except StopIteration:
        raise KeyError(f"unknown function for {library!r}; choose from {tuple(FUNCTIONS[library].values())}") from None

@dataclass
class SilentStoreOptions:
    only_initialized_memory: bool = True
    restrict_values_to_check: Optional[List[int]] = None

@dataclass
class RegisterFileCompresionOptions:
    restrict_values_to_check: Optional[List[int]] = None

@dataclass
class NarrowRegisterFileCompresionOptions:
    same_register_allowed: bool = True

@dataclass
class ComputationSimplificationOptions:
    only_trivial_ops: bool = False

@dataclass
class NarrowComputationSimplificationOptions:
    pass

@dataclass
class OperandPackingOptions:
    reservation_update_unit_size: int = 200

@dataclass
class ComputationReuseOptions:
    reuse_buffers_size: int = 500
    n_entries_per_pc: int = 10
    reuse_loads: bool = True
    reuse_addr_calc: bool = True

@dataclass
class CacheCompressionOptions:
    compression_alg: str
    cache_line_size: int = 64

@dataclass
class PrefetcherOptions:
    model: str
    cache_line_size: int = 64
    page_size: int = 4096
    needs_hits: int = 3
    pointer_size: int = 8


class ConfCls:
    config_path: str = ""

    # algorithm: str = 'salsa'
    # algorithm: str = 'curve25519'
    # algorithm: str = 'sha512'
    # algorithm: str = 'poly1305'
    # algorithm: str = 'stream_xor'
    # algorithm: str = 'secretbox'
    # algorithm: str = 'auth'
    algorithm: str = 'x25519'
    # algorithm: str = 'aes_enc'

    library: str = 'libsodium'
    # library: str = 'nacl'
    # library: str = 'openssl'
    speculation_window: int = 200
    nesting_window: int = 50
    check_results: bool = False

    # ==============================================================================================
    # Model and tracer
    model: str = 'x86-unicorn'

    tracer: str = 'narrow-computation-simplification'
    leakage_name: str = ''
    tracer_options = None

    # tracer: str = 'operand-packing'
    # tracer_options = OperandPackingOptions(reservation_update_unit_size=200)

    # tracer: str = 'computation-reuse'
    # tracer_options = ComputationReuseOptions(reuse_buffers_size=500, n_entries_per_pc=4, reuse_loads=True, reuse_addr_calc=True)

    # tracer: str = 'constant-time'
    # tracer_options=None

    # ==============================================================================================
    # Input generator
    random_input_gen_seed: Optional[int] = None

    # ==============================================================================================
    # Analyser
    analyser: str = 'equivalence-classes'

    # ==============================================================================================
    # ==============================================================================================
    # Output
    multiline_output: bool = False
    logging_modes: List[str] = ["info", "stat", "report_violations"]

    def load(self, conf_path):
        self.config_path = conf_path
        with open(conf_path, "r") as f:
            config_update: Dict = yaml.safe_load(f)
        for var, value in config_update.items():
            self.set(var, value)

    def save(self, conf_path):
        pass
        # with open(conf_path, "w") as f:
        #     yaml.safe_dump(self.__dict__, f)

    def set(self, name, value):
        def set(obj, name, value):
            # Inherited from revizor, I haven't taken a look into it yet
            # options = {
            #     'program': ['salsa', 'curve25519', 'sha512', 'poly1305'],
            #     'model': ['x86-unicorn'],
            #     'tracer': ['silent-store', 'silent-store-initialized-mem', 'register-file-compression'],
            # }

            if name[0] == "_":
                raise ConfigException(f"Attempting to set an internal configuration variable {name}.")
            if not hasattr(obj, name):
                raise ConfigException(f"Unknown configuration variable {name}.\n"
                                    f"It's likely a typo in the configuration file.")
            # if type(obj.__getattribute__(name)) != type(value):
            #     raise ConfigException(f"Wrong type of the configuration variable {name}.\n"
            #                         f"It's likely a typo in the configuration file.")

            # value checks
            # if options.get(name, '') != '' and value not in options[name]:
            #     raise ConfigException(f"Unknown value '{value}' of configuration variable '{name}'")

            obj.__setattr__(name, value)

        if name == "tracer_options":
            self.tracer_options = {
                "silent-store": SilentStoreOptions,
                "register-file-compression": RegisterFileCompresionOptions,
                "narrow-register-file-compression": NarrowRegisterFileCompresionOptions,
                "computation-simplification": ComputationSimplificationOptions,
                "narrow-computation-simplification": NarrowComputationSimplificationOptions,
                "operand-packing": OperandPackingOptions,
                "computation-reuse": ComputationReuseOptions,
                "constant-time": None,
            }[self.tracer]()
            if value is None:
                return
            if not isinstance(value, dict):
                raise ConfigException("Bad tracer options")
            for k, v in value.items():
                set(self.tracer_options, k, v)
        else:
            set(self, name, value)

CONF = ConfCls()

class ConfigException(Exception):
    pass

TRACERS = {
    "constant-time": [
        ("ct", None),
    ],
    "silent-store": [
        ("ss", SilentStoreOptions(only_initialized_memory=False, restrict_values_to_check=None)),
        ("ssi", SilentStoreOptions(only_initialized_memory=True, restrict_values_to_check=None)),
        ("ssi0", SilentStoreOptions(only_initialized_memory=True, restrict_values_to_check=[0])),
    ],
    "register-file-compression": [
        ("rfc", RegisterFileCompresionOptions(restrict_values_to_check=None)),
        ("rfc0", RegisterFileCompresionOptions(restrict_values_to_check=[0])),
    ],
    "narrow-register-file-compression": [
        ("nrfc", NarrowRegisterFileCompresionOptions(same_register_allowed=True)),
    ],
    "computation-simplification": [
        ("cs", ComputationSimplificationOptions(only_trivial_ops=False)),
        ("cst", ComputationSimplificationOptions(only_trivial_ops=True)),
    ],
    "narrow-computation-simplification": [
        ("ncs", None),
    ],
    "operand-packing": [
        ("op", OperandPackingOptions(reservation_update_unit_size=200))
    ],
    "computation-reuse": [
        ("cr", ComputationReuseOptions(reuse_buffers_size=500, n_entries_per_pc=4, reuse_loads=True, reuse_addr_calc=False)),
        ("cra", ComputationReuseOptions(reuse_buffers_size=500, n_entries_per_pc=4, reuse_loads=True, reuse_addr_calc=True)),
    ],
    "cache-compression": [
        ("cc-fpc", CacheCompressionOptions(compression_alg="fpc")),
        ("cc-bdi", CacheCompressionOptions(compression_alg="bdi")),
    ],
    "prefetcher": [
        ("pf-nl", PrefetcherOptions(model="nextline", needs_hits=0)),
        ("pf-stream", PrefetcherOptions(model="stream", needs_hits=3)),
        ("pf-m1", PrefetcherOptions(model="m1", needs_hits=3, pointer_size=8)),
    ],
}