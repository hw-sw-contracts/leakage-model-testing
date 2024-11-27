"""
File: Custom data types

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

from typing import List, Dict, Tuple, Optional, NamedTuple, Any
from recordclass import RecordClass, asdict, astuple
from collections import defaultdict
from abc import ABC, abstractmethod
from enum import Enum
from config import CONF
import copy
import binascii

generate_count = 0

# ==================================================================================================
# Custom Data Types
# ==================================================================================================

class Registers(RecordClass):
    rax: Optional[int] = None
    rbx: Optional[int] = None
    rcx: Optional[int] = None
    rdx: Optional[int] = None
    rbp: Optional[int] = None
    rsp: Optional[int] = None
    rsi: Optional[int] = None
    rdi: Optional[int] = None
    r8:  Optional[int] = None
    r9:  Optional[int] = None
    r10: Optional[int] = None
    r11: Optional[int] = None
    r12: Optional[int] = None
    r13: Optional[int] = None
    r14: Optional[int] = None
    r15: Optional[int] = None

    def __str__(self):
        s = ""
        for k, v in asdict(self).items():
            if v is None:
                v = 0
            s += f"{k:3s}: {v:#018x}\n"
        return s

X86_ABI = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']


class Input(NamedTuple):
    params: dict[str, Any]
    stack: bytes
    stack_addr: int
    regs: Registers
    mem_initialized: set[int]

    def arg_to_n(self, arg: str | int) -> int:
        if isinstance(arg, str):
            arg = next(i for i, name in enumerate(self.params.keys()) if name == arg)
        return arg

    @property
    def lengths(self) -> dict[int, int]:
        lengths = {}
        for reg, param in zip(X86_ABI, self.params.values()):
            match param:
                case _, "lengthof", int(n):
                    lengths[n] = getattr(self.regs, reg)
        for i, param in enumerate(self.params.values()):
            match param:
                case _, ("aliasout"|"samelenout"), int(n):
                    lengths[i] = lengths[n]
                case _, "samelenout", (int(n), int(add)):
                    lengths[i] = lengths[n] + add
                case _, "samelenout", (int(n), fn):
                    lengths[i] = fn(lengths[n])
        return lengths

    def get_arg(self, arg: int | str, stack=None) -> bytes:
        if stack is None:
            stack = self.stack
        if isinstance(arg, int):
            n = arg
            param = list(self.params.values())[n]
        else:
            n, param = next(
                (i, param)
                for i, (name, param) in enumerate(self.params.items())
                if name == arg
            )
        regval = getattr(self.regs, X86_ABI[n])
        match param:
            case _, ("in"|"out"), int(length):
                data = self.slice(stack, regval, length)
            case _ if (length := self.lengths.get(n)) is not None:
                data = self.slice(stack, regval, length)
            case _:
                raise NotImplementedError([arg, param, self.lengths])
        return data

    def public_observation(self) -> Input:
        pubs = []
        for name, param in self.params.items():
            match param:
                case "public", "in", bytes():
                    pass
                case "public", "in", _:
                    pubs.append(self.get_arg(name))
        return Input(
            params=self.params, stack=b''.join(pubs), stack_addr=0, regs=Registers(),
            mem_initialized=set()
        )

    # TODO: deprecate this and replace with explicit calls to get_arg(...)
    def get_result(self, stack_result: bytes) -> bytes:
        results = []
        for name, param in self.params.items():
            match param:
                case _, ("out"|"aliasout"), _:
                    results.append(self.get_arg(name, stack=stack_result))
        return b''.join(results)

    def slice(self, stack, addr, length):
        offset = addr - self.stack_addr # negative offset
        return slice(stack, offset, length)

    def __hash__(self):
        return hash((self.stack, astuple(self.regs)))

    def deterministic_hash(self):
        # avoid hash() on None and bytes, since it produces non deterministic results
        regs = tuple(reg for reg in self.regs if reg is not None)
        stack_hash = 0
        for b in self.stack:
            stack_hash = ( stack_hash*281  ^ b*997) & 0xFFFFFFFFFFFFFFFF
        return hash(regs) ^ stack_hash

class Trace(NamedTuple):
    trace: RawTrace
    details: None = None

    def observation(self, i: int) -> str:
        return self.trace[i]

    def trace_with_details(self):
        return (self.observation(i) for i in range(len(self.trace)))

RawTrace = Tuple[str, ...]
TraceHash = int
InputID = int
# TraceGroup = List[Measurement]
TraceMap = Dict[TraceHash, List[InputID]]

class Measurement(NamedTuple):
    input_id: InputID
    input_: Input
    trace: Trace


class EquivalenceClass:
    # All these measurement have the same public data
    pub: Input
    measurements: List[Measurement]

    # Map from trace hash to ids of inputs with that trace
    trace_map: TraceMap

    MOD2P64 = pow(2, 64)

    def __init__(self) -> None:
        self.measurements = []

    def __len__(self):
        return len(self.measurements)

    def build_trace_map(self) -> None:
        """ group inputs by htraces """
        groups = defaultdict(list)
        for measurement in self.measurements:
            trace = measurement.trace.trace
            groups[hash(trace)].append(measurement.input_id)
        self.trace_map = groups




# ==================================================================================================
# Interfaces of Modules
# ==================================================================================================
def slice(stack, offset, length):
    offset_end = offset + length
    ret = stack[offset:offset_end] if offset_end else stack[offset:]
    assert len(ret) == length
    return ret

def SecretOut(nbytes):
    return ("secret", "out", nbytes)
def SecretAliasOut(arg):
    return ("secret", "aliasout", arg)
def SecretOutSameLen(arg, add=0, fn=None):
    return ("secret", "samelenout", arg if not add and not fn else (arg, fn) if not add else (arg, add))
def SecretIn(len_or_minlen, maxlen=None):
    if maxlen is not None:
        return ("secret", "in", (len_or_minlen, maxlen))
    return ("secret", "in", len_or_minlen)
def PublicOut(nbytes):
    return ("public", "out", nbytes)
def PublicIn(len_or_minlen, maxlen=None, fn=None):
    if maxlen is not None:
        if fn is not None:
            return ("public", "in", (len_or_minlen, maxlen, fn))
        return ("public", "in", (len_or_minlen, maxlen))
    return ("public", "in", len_or_minlen)
def FixedIn(data):
    return ("public", "in", data)
def LengthOf(arg):
    return ("public", "lengthof", arg)

class StackState():
    address: int
    size: int
    content: bytes
    mem_initialized: set[int]

    def __init__(self, address, size):
        self.address = address
        self.size = size
        self.content = b""
        self.mem_initialized = set()

    def push(self, content, initialized=True):
        self.address -= len(content)
        if initialized:
            cur = len(self.content)
            self.mem_initialized.update(range(cur, cur+len(content)))
        self.content = content + self.content
        assert len(self.content) <= self.size
        return self.address

    def push_null(self, length, initialized=False):
        return self.push(b"\x00"*length, initialized)

    def push_rsp(self):
        # Align stack first. For some reason, writing to unaligned memory addresses
        # triggers unicorn memory access hook several times, one for each byte writen.
        self.push_null(self.address % 8)
        return self.push_null(8)

    # def get_final_content(self):
    #     return self.content


class InputGenerator(ABC):
    stack_addr: int
    stack_size: int

    def __init__(self, stack_addr: int, stack_size: int):
        self.stack_addr = stack_addr
        self.stack_size = stack_size

    @abstractmethod
    def get_signature(self) -> list[Any] | dict[str, Any]:
        pass

    @abstractmethod
    def check_result(self, input_: Input, stack_result: bytes) -> None:
        pass

    def create_input(self, params, args) -> Input:
        arg = iter(args)
        stack = StackState(self.stack_addr, self.stack_size)
        regs = Registers()

        stacked = {}

        # enstack and set args
        slot = iter(X86_ABI)
        for i, param in enumerate(params.values()):
            reg = next(slot)
            match param:
                case _, "out", int(length):
                    addr = stack.push_null(length)
                    stacked[i] = (addr, length)
                    setattr(regs, reg, addr)
                case _, "in", bytes(data):
                    addr = stack.push(data)
                    stacked[i] = (addr, len(data))
                    setattr(regs, reg, addr)
                case _, "in", _:
                    data = next(arg)
                    addr = stack.push(data)
                    stacked[i] = (addr, len(data))
                    setattr(regs, reg, addr)
                case _, "n", int(n):
                    setattr(regs, reg, n)

        # backfill any args that are aliases or lengths
        slot = iter(X86_ABI)
        for param in params.values():
            reg = next(slot)
            match param:
                case _, "aliasout", int(n):
                    setattr(regs, reg, stacked[n][0])
                case _, "samelenout", int(n):
                    addr = stack.push_null(stacked[n][1])
                    setattr(regs, reg, addr)
                case _, "samelenout", (int(n), int(add)):
                    addr = stack.push_null(stacked[n][1] + add)
                    setattr(regs, reg, addr)
                case _, "samelenout", (int(n), fn):
                    addr = stack.push_null(fn(stacked[n][1]))
                    setattr(regs, reg, addr)
                case _, "lengthof", int(n):
                    setattr(regs, reg, stacked[n][1])

        regs.rsp = stack.push_rsp()
        regs.rbp = regs.rsp

        return Input(
            params=params,
            stack=stack.content,
            stack_addr=self.stack_addr,
            mem_initialized=stack.mem_initialized,
            regs=regs,
        )

    @staticmethod
    def _normalize_params(_params):
        params = {}
        names = list(_params.keys())
        for name, param in _params.items():
            match param:
                case lbl, (("aliasout"|"samelenout"|"lengthof") as ty), str(arg):
                    param = (lbl, ty, names.index(arg))
                case lbl, ("samelenout" as ty), (str(arg), n):
                    param = (lbl, ty, (names.index(arg), n))
            params[name] = param
        return params

    def generate(self, count: int) -> List[Input]:
        input_str = ""
        input_bytes = {}
        params = self.get_signature()
        if isinstance(params, list):
            params = {f"arg{i}": self._normalize_param(param) for i, param in enumerate(params)}
        params = self._normalize_params(params)
        inputs: List[Input] = []
        pubargs = []

        # get lengths for all input buffers
        # and also generate public random bytes
        secret_index = 0
        secret_len = 0
        secret_param = ""
        for inp, param in params.items():
            lbl, length = None, None
            match param:
                case str(lbl), "in", int(length):
                    pass
                case str(lbl), "in", (int(minlen), int(maxlen)):
                    length = self.randint(minlen, maxlen)
                case str(lbl), "in", (int(minlen), int(maxlen), fn):
                    length = fn(self.randint(minlen, maxlen))
            if lbl == "public":
                pubargs.append(self.random_bytes(length))
                input_bytes[str(inp)] = pubargs[-1]
                input_str += str(inp) + ':' + str(binascii.hexlify(pubargs[-1]).decode('ascii')) + "\n"
            elif lbl == "secret":
                input_bytes["key_len"] = length
                secret_param += str(inp)
                input_str += str(inp) + ':' + str(length) + "\n"
                pubargs.append(length)
                secret_len=length
                secret_index=len(pubargs)-1

        # generate secret random bytes
        # and construct inputs
        for i in range(count):
            pubargs[secret_index]=self.random_bytes(secret_len)
            if i == 0:
                input_bytes[secret_param] = pubargs[secret_index]
            else: 
                input_bytes["secret"+str(i)] = pubargs[secret_index]
            input_str += "secret:" + str(binascii.hexlify(pubargs[secret_index]).decode('ascii')) + "\n"
            inputs.append(
                self.create_input(
                    params,
                    pubargs
                )
            )
        inputs.append(input_str)
        inputs.append(input_bytes)
        return inputs

    def generate_constant(self, count: int, index: int) -> List[Input]:
        params = self.get_signature()
        if isinstance(params, list):
            params = {f"arg{i}": self._normalize_param(param) for i, param in enumerate(params)}
        params = self._normalize_params(params)
        inputs: List[Input] = []
        pubargs = []

        # get lengths for all input buffers
        # and also generate public random bytes
        secret_index = 0
        secret_len = 0
        for arg, param in params.items():
            if arg == "result" or "len" in arg:
                continue
            elif param[0] == 'secret' and param[1] == 'in':
                pubargs.append(bytearray(self.VECTORS[index][arg]))
                secret_len=param[2]
                secret_index=len(pubargs)-1
            else:
                pubargs.append(bytearray(self.VECTORS[index][arg]))
                
        inputs.append(self.create_input(params, pubargs))
        if "secret1" in self.VECTORS[index]:
            pubargs[secret_index] = bytearray(self.VECTORS[index]["secret1"])
        else:
            pubargs[secret_index] = self.random_bytes(secret_len)
        # compare agianst random input
        inputs.append(self.create_input(params, pubargs))
        return inputs

    def slice(self, stack, addr, length):
        offset = addr - self.stack_addr # negative offset
        return slice(stack, offset, length)


class Model(ABC):
    @abstractmethod
    def trace_test_case(self, input_: Input) -> Tuple[Trace, int]:
        pass

    @abstractmethod
    def get_stack(self) -> bytes:
        pass

class Analyser(ABC):
    @abstractmethod
    def filter_violations(self,
                          inputs: List[Input],
                          pubs: List[Input],
                          traces: List[Trace],
                          stats=False) -> List[EquivalenceClass]:
        pass
