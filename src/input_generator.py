"""
File: Input Generation

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import ctypes
import random
from typing import List, Tuple

from config import CONF, ConfigException
from test_vectors import TEST_VECTORS
from saved_test import SAVED_TEST
from zero_vectors import ZERO_VECTORS
from interfaces import (
    FixedIn,
    Input,
    InputGenerator,
    LengthOf,
    PublicIn,
    PublicOut,
    Registers,
    SecretAliasOut,
    SecretIn,
    SecretOut,
    SecretOutSameLen,
    StackState,
)
from service import LOGGER

POW32 = pow(2, 32)

def create_input(gen: InputGenerator, *args):
    stack = StackState(gen.stack_addr, gen.stack_size)
    regs = Registers()

    abi = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
    slot = iter(abi)
    matches = []
    for ty, arg in args:
        reg = next(slot)
        if ty == "out":
            setattr(regs, reg, stack.push_null(arg))
        elif ty == "in":
            setattr(regs, reg, stack.push(arg))
        elif ty == "n":
            setattr(regs, reg, arg)
        elif ty == "match":
            matches.append((reg, abi[arg]))
    for dst, src in matches:
        setattr(regs, dst, getattr(regs, src))

    regs.rsp = stack.push_rsp()
    regs.rbp = regs.rsp

    return Input(stack=stack.content, mem_initialized=stack.mem_initialized, regs=regs)

# TODO separate logic of input registers and stack layout vs random input generation

class RandomInputGenerator(InputGenerator):
    def __init__(self, stack_addr, stack_size):
        super().__init__(stack_addr, stack_size)
        seed = CONF.random_input_gen_seed
        if seed is None:
            seed = random.randint(0, POW32)
        random.seed(seed)
        LOGGER.info("input_gen", "seed: " + str(seed))

    def randint(self, min, max):
        return random.randint(min, max)

    def random_bytes(self, n):
        return random.randbytes(n)

class SalsaInputGenerator(RandomInputGenerator):
    KEYBYTES = 32
    NONCEBYTES = 8
    VECTORS = ZERO_VECTORS["salsa"] + TEST_VECTORS["salsa"]

    def get_signature(self):
        return {
            "result": SecretOutSameLen("message"),
            "message": PublicIn(4, 256),
            "len": LengthOf("message"),
            "key": SecretIn(self.KEYBYTES),
            "nonce": PublicIn(self.NONCEBYTES),
        }

    def check_result(self, input_: Input, stack_result: bytes) -> None:
        # get the result from the stack
        result = input_.get_arg("result", stack_result)

        # get the real result
        c = ctypes.CDLL("targets/libsodium.so")
        message = input_.get_arg("message")
        nonce = input_.get_arg("nonce")
        key = input_.get_arg("key")
        out = ctypes.create_string_buffer(len(message))
        c.crypto_stream_salsa20_xor(out, message, len(message), nonce, key)
        out = bytes(out)

        if result != out:
            LOGGER.emulation_error(out, result)

class StreamXorInputGenerator(RandomInputGenerator):
    KEYBYTES = 32
    NONCEBYTES = 24

    SECRETBYTES = KEYBYTES

    IN_PLACE = False
    VECTORS = ZERO_VECTORS["stream_xor"] + TEST_VECTORS["stream_xor"]

    def get_signature(self):
        return {
            "result": SecretAliasOut("message") if self.IN_PLACE else SecretOutSameLen("message"),
            "message": PublicIn(4, 256),
            "len": LengthOf("message"),
            "nonce": PublicIn(self.NONCEBYTES),
            "key": SecretIn(self.KEYBYTES),
        }

    def check_result(self, input_: Input, stack_result: bytes) -> None:
        # get the result from the stack
        result = input_.get_arg("result", stack_result)

        # get the real result
        c = ctypes.CDLL("targets/libsodium.so")
        message = input_.get_arg("message")
        nonce = input_.get_arg("nonce")
        key = input_.get_arg("key")
        out = ctypes.create_string_buffer(len(message))
        c.crypto_stream_xor(out, message, len(message), nonce, key)
        out = bytes(out)

        if result != out:
            LOGGER.emulation_error(out, result)


class Curve25519InputGenerator(RandomInputGenerator):
    # Constants from libsodium
    SECRETKEYBYTES = 64
    BYTES = 64
    SECRETBYTES = SECRETKEYBYTES
    VECTORS = ZERO_VECTORS["ed25519"] + TEST_VECTORS["ed25519"]

    def get_signature(self):
        return {
            "result": SecretOutSameLen("message", add=self.BYTES),
            "result_len": PublicOut(8),
            "message": PublicIn(4, 64),
            "len": LengthOf("message"),
            "key": SecretIn(self.SECRETKEYBYTES),
        }

    def check_result(self, input_: Input, stack_result: bytes) -> None:
        # get the result from the stack
        result_len = int.from_bytes(input_.get_arg("result_len", stack_result), "little")
        result = input_.get_arg("result", stack_result)

        # get the real result
        c = ctypes.CDLL("targets/libsodium.so")
        message = input_.get_arg("message")
        key = input_.get_arg("key")
        signed_message = ctypes.create_string_buffer(len(message) + self.BYTES)
        signed_message_len = ctypes.c_ulonglong()
        c.crypto_sign_ed25519(signed_message, ctypes.byref(signed_message_len),
                              message, len(message), key)
        signed_message = bytes(signed_message)[:signed_message_len.value]

        if result != signed_message:
            LOGGER.emulation_error(signed_message, result)


class SHA512InputGenerator(RandomInputGenerator):
    BYTES = 64
    VECTORS = ZERO_VECTORS["sha512"] + TEST_VECTORS["sha512"]
    def get_signature(self):
        return {
            "result": SecretOut(self.BYTES),
            "data": SecretIn(4, 256),
            "len": LengthOf("data"),
        }

    def check_result(self, input_: Input, stack_result: bytes) -> None:
        # get the result from the stack
        result = input_.get_arg("result", stack_result)

        # get the real result
        c = ctypes.CDLL("targets/libsodium.so")
        data = input_.get_arg("data")
        out = ctypes.create_string_buffer(self.BYTES)
        c.crypto_hash_sha512(out, data, len(data))
        out = bytes(out)
        if result != out:
            LOGGER.emulation_error(out, result)

class Poly1305InputGenerator(RandomInputGenerator):
    KEYBYTES = 32
    BYTES = 16
    VECTORS = ZERO_VECTORS["poly1305"] + TEST_VECTORS["poly1305"]

    def get_signature(self):
        return {
            "result": SecretOut(self.BYTES),
            "message": PublicIn(4, 256),
            "len": LengthOf("message"),
            "key": SecretIn(self.KEYBYTES),
        }

    def check_result(self, input_: Input, stack_result: bytes) -> None:
        # get the result from the stack
        result = input_.get_arg("result", stack_result)
        # get the real result
        c = ctypes.CDLL("targets/libsodium.so")
        message = input_.get_arg("message")
        key = input_.get_arg("key")
        mac = ctypes.create_string_buffer(self.BYTES)
        signed_message_len = ctypes.c_ulonglong()
        c.crypto_onetimeauth_poly1305(mac, message, len(message), key)
        mac = bytes(mac)

        if result != mac:
            LOGGER.emulation_error(mac, result)

class AuthInputGenerator(RandomInputGenerator):
    KEYBYTES = 32
    BYTES = 32
    SECRETBYTES = KEYBYTES
    VECTORS = ZERO_VECTORS["hmac"] + TEST_VECTORS["hmac"]

    def get_signature(self):
        return {
            "result": SecretOut(self.BYTES),
            "message": PublicIn(4, 256),
            "len": LengthOf("message"),
            "key": SecretIn(self.KEYBYTES),
        }

    def check_result(self, input_: Input, stack_result: bytes) -> None:
        # get the result from the stack
        result = input_.get_arg("result", stack_result)
        # get the real result
        c = ctypes.CDLL("targets/libsodium.so")
        message = input_.get_arg("message")
        key = input_.get_arg("key")
        out = ctypes.create_string_buffer(self.BYTES)
        c.crypto_auth(out, message, len(message), key)
        out = bytes(out)

        if result != out:
            LOGGER.emulation_error(out, result)

class X25519InputGenerator(RandomInputGenerator):
    PUBLICKEYBYTES = 32
    SECRETKEYBYTES = 32
    BEFORENMBYTES  = 32
    SECRETBYTES = SECRETKEYBYTES
    VECTORS = ZERO_VECTORS["x25519"] + TEST_VECTORS["x25519"]

    def get_signature(self):
        return {
            "result": SecretOut(self.BEFORENMBYTES),
            "public_key": PublicIn(self.PUBLICKEYBYTES),
            "secret_key": SecretIn(self.SECRETKEYBYTES),
        }

    def check_result(self, input_: Input, stack_result: bytes) -> None:
        # get the result from the stack
        result = input_.get_arg("result", stack_result)
        # get the real result
        c = ctypes.CDLL("targets/libsodium.so")
        public_key = input_.get_arg("public_key")
        secret_key = input_.get_arg("secret_key")
        out = ctypes.create_string_buffer(self.BEFORENMBYTES)
        c.crypto_scalarmult_curve25519(out, public_key, secret_key)
        out = bytes(out)

        if result != out:
            LOGGER.emulation_error(out, result)


AES_ENCRYPT = 1
AES_MAXNR = 14
class AES_KEY(ctypes.Structure):
    _fields_ = [
        ("rd_key", ctypes.c_int*4*(AES_MAXNR + 1)),
        ("rounds", ctypes.c_int),
    ]

class AESEncryptInputGenerator(RandomInputGenerator):
    KEYBYTES = 128//8
    AES_BLOCK_SIZE = 16

    SECRETBYTES = KEYBYTES
    VECTORS = ZERO_VECTORS["aes_cbc"] + TEST_VECTORS["aes_cbc"]

    def output_length(self, input_length):
        return (input_length + self.AES_BLOCK_SIZE - 1) & ~(self.AES_BLOCK_SIZE - 1)

    def get_signature(self):
        return {
            "result": SecretOutSameLen("message"),
            "message": PublicIn(4, 256, fn=self.output_length),
            "len": LengthOf("message"),
            "key": SecretIn(self.KEYBYTES),
            "iv": PublicIn(self.AES_BLOCK_SIZE),
        }

    def check_result(self, input_: Input, stack_result: bytes) -> None:
        return None


def get_input_generator(stack_addr, stack_size) -> InputGenerator:
    options = {
        "salsa": SalsaInputGenerator,
        "stream_xor": StreamXorInputGenerator,
        "ed25519": Curve25519InputGenerator,
        "sha512": SHA512InputGenerator,
        "poly1305": Poly1305InputGenerator,
        "hmac": AuthInputGenerator,
        "x25519": X25519InputGenerator,
        "aes_cbc": AESEncryptInputGenerator
    }
    if CONF.algorithm not in options:
        raise ConfigException("unknown program in config.py")
    return options[CONF.algorithm](stack_addr, stack_size)
