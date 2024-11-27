"""
File: Model Interface and its implementations

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from bitstring import Bits, BitArray
from collections import defaultdict as ddict, deque
from contextlib import suppress
from pathlib import Path
from typing import NamedTuple

import os 
import unicorn as uni
import copy
import re
import json
import itertools
import time # exit a round after a set time
from ruamel.yaml import YAML
from unicorn import Uc, UcError, UC_MEM_WRITE, UC_MEM_READ
from unicorn.x86_const import *

import iced_x86

from typing import List, Tuple, Dict, Optional, Set, Callable, Union

from interfaces import Input, Model, Registers, Trace
from elf_parser import ElfParser
from config import CONF, ConfigException, get_algorithm
from service import LOGGER, MASK_64BIT
from helpers import set_fs, SCRATCH_ADDR, SCRATCH_SIZE

import hy
from tracers import leakage_models, execution_models
from tracers.tracing import HALT
from ctypes import CDLL
cc_models = CDLL('./targets/cc_models.so')
import capstone
from capstone.x86 import *
from dataclasses import dataclass
yaml = YAML(typ='safe')

# Same registers and order as in Registers
UNICORN_REGS = [
    UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
    UC_X86_REG_RBP, UC_X86_REG_RSP, UC_X86_REG_RSI, UC_X86_REG_RDI,
    UC_X86_REG_R8,  UC_X86_REG_R9,  UC_X86_REG_R10, UC_X86_REG_R11,
    UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
]
UNICORN_REGS_NAMES = [
    "RAX", "RBX", "RCX", "RDX",
    "RBP", "RSP", "RSI", "RDI",
    "R8", "R9", "R10", "R11",
    "R12", "R13", "R14", "R15",
]

UC_PROT_NONE = 0
UC_PROT_READ = 1
UC_PROT_WRITE = 2
UC_PROT_EXEC = 4
UC_PROT_ALL = 7

STUB_ADDR = 0x1000
TIMEOUT = 1800

ICED_rlookup = {v: k for k, v in vars(iced_x86.Register).items() if isinstance(v, int)}

def disasm_inst(cs: capstone.Cs, emu: Uc, address: int, size: int):
    return next(cs.disasm(emu.mem_read(address, size), address))

class CheckPoint(NamedTuple):
    # stores area of memory with write permission
    address_space: list
    predictions: list
    # store execution state prior to speculative execution
    stack: bytes
    flag: int
    context: unicorn.unicorn.UcContext
    reorder_buffer: int

# ==================================================================================================
# Abstract Interface
# ==================================================================================================
class X86UnicornTracer(ABC):
    trace: List[str]
    details: List[str]
    cs: capstone.Cs

    def __init__(self):
        super().__init__()
        self.trace = []
        self.details = []

    def reset_trace(self) -> None:
        self.trace = []
        self.details = []

    def start_tracing(self, model: X86UnicornModel, input_: Input) -> None:
        pass

    def get_trace(self) -> Trace:
        return Trace(trace=tuple(self.trace), details=tuple(self.details))

    def add_to_trace(self, address: int, details: str = None):
        self.trace.append(hex(address))
        self.details.append(details if details else "")

    @abstractmethod
    def mem_access_hook(self, emulator: Uc, access: int, address: int, size: int, value: int, model: X86UnicornModel) -> None:
        pass

    @abstractmethod
    def instruction_hook(self, emulator: Uc, address: int, size: int, model: X86UnicornModel) -> None:
        pass


class DummyTracer(X86UnicornTracer):
    def mem_access_hook(self, emulator: Uc, access: int, address: int, size: int, value: int, model: Model) -> None:
        pass

    def instruction_hook(self, emulator: Uc, address: int, size: int, model: Model) -> None:
        pass


class State:
    def __init__(self, input_: Input, tracer_state):
        self.input_ = input_
        self.tracer_state = tracer_state

# Model
class X86UnicornModel(Model):
    """
    Base class for all Unicorn-based models.
    Serves as an adapter between Unicorn and our fuzzer.
    """
    STACK_SIZE: int
    STACK: int
    STACK_TOP: int
    STUB_ADDR = 0x1000

    TCB_ALIGNMENT = 64
    HEAP_BASE = 0x10000

    emulator: Uc
    tracer: X86UnicornTracer
    symbols: ElfParser
    cs: capstone.Cs

    code_start: int
    code_end: int

    address_start = STUB_ADDR
    address_end = STUB_ADDR + 5

    instruction_count: int = 0
    prev_pc: int = 0
    prev_predictions: list = []
    branch_count: int = 0
    enable_speculative_execution = False
    speculative = False
    reorder_buffer: int = 0
    # determines how many instruction can be speculatively executed
    write_start_addresses = []
    write_size = []
    checkpoints = []
    SPECULATION_WINDOW = CONF.speculation_window
    MAX_NESTING = CONF.nesting_window

    SERIALIZING_INSTR = {
        X86_INS_MFENCE,
        X86_INS_LFENCE,
        X86_INS_SFENCE,
        X86_INS_CPUID,
        X86_INS_IRET,
    }

    def __init__(self, path, function_name, predictors):
        self.binary_path = Path(path)
        self.library = self.binary_path.name
        self.function_name = function_name
        self.algorithm = get_algorithm(self.function_name, self.library)
        self.dumps_path = Path('violations_db') / f'{self.algorithm}-{self.library}' / 'dumps'
        # self.elf = ElfParser(path)
        self._load_elf()
        self._mapped = set()
        self._segments = set()
        self._decoders = {}
        self._iifactory = iced_x86.InstructionInfoFactory()
        self.curbrk = None
        self._fs = None
        self.function_addr = self.elf['symtable'][function_name]['addr']
        self._patches = {}
        self.enable_speculative_execution = True if predictors else False
        self.predictors = load_predictors(predictors)
        self._load_program()
        self.prev_mem_dump = None
        self.cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    
    @staticmethod
    def _aligndown(addr, alignment):
        return addr // alignment * alignment

    @staticmethod
    def _alignup(sz, alignment):
        return ((sz - 1) // alignment + 1) * alignment

    def _load_elf(self):
        with (self.dumps_path / 'elf_info.yaml').open() as fp:
            self.elf = yaml.load(fp)
        revsym = ddict(list)
        for sym, entry in self.elf['symtable'].items():
            revsym[entry['addr']].append(sym)
        self.revsym = revsym

    def _patch_got(self):
        reloc = self.elf['relocations']
        for entry in reloc:
            self.emulator.mem_write(entry['addr'], entry['dest'].to_bytes(8, "little"))
            self._patches[entry['dest']] = self.revsym[entry['dest']]

    def is_mapped(self, addr):
        page = self._aligndown(addr, 0x1000)
        return page in self._mapped

    def mem_map(self, start, size, perms=None):
        start = self._aligndown(start, 0x1000)
        end = self._alignup(start + size, 0x1000)
        size = end - start
        startn = start // 0x1000
        endn = end // 0x1000
        if not self._mapped.intersection(range(startn, endn)):
            if perms is not None:
                self.emulator.mem_map(start, size, perms)
            else:
                self.emulator.mem_map(start, size)
        else:
            for page in set(range(startn, endn)).difference(self._mapped):
                self.emulator.mem_map(page * 0x1000, 0x1000, perms)
        self._mapped.update(range(startn, endn))
        self._segments.add((start, start + size))

    def _load_program(self) -> None:
        self.emulator = Uc(uni.UC_ARCH_X86, uni.UC_MODE_64)

        # set up callbacks
        # self.emulator.hook_add(uni.UC_HOOK_MEM_INVALID, self.mem_access_unmapped_hook, self)
        self.emulator.hook_add(uni.UC_HOOK_MEM_READ | uni.UC_HOOK_MEM_WRITE,
                        self.mem_access_hook, self)
        if not self.enable_speculative_execution:
            self.emulator.hook_add(uni.UC_HOOK_CODE, self.instruction_hook, self)
        else:
            self.emulator.hook_add(uni.UC_HOOK_CODE, self.speculate_instruction_hook, self)
        self.emulator.hook_add(uni.UC_HOOK_INSN_INVALID, self.instruction_invalid, self)
        self._import_dumps(brief=True)

    def _import_dumps(self, brief=False):
        uc = self.emulator
        blob = json.loads((self.dumps_path / 'dump_data.json').read_text())
        last = None
        self.write_start_addresses.clear()
        self.write_size.clear()
        perm = 0
        for start, end, size, offset, perms, file in blob['mappings']:
            #print("start = ", hex(start), "end = ", hex(end), "size = ", hex(size), "offset = ", hex(offset), perms)
            if (path := (self.dumps_path / f'dump_{start:x}_{end:x}.bin')).is_file():
                if file == '[stack]':
                    self.STACK = end
                    self.STACK_SIZE = size
                    self.STACK_TOP = self.STACK - self.STACK_SIZE
                if 'w' in perms:
                    perm = perm | UC_PROT_WRITE
                if 'w' in perms and file != '[stack]':
                    self.write_start_addresses.append(int(start))
                    self.write_size.append(int(size))
                if 'r' in perms:
                    perm = perm | UC_PROT_READ
                if 'x' in perms:
                    perm = perm | UC_PROT_EXEC
            else:
                continue
            data = path.read_bytes()
            self.mem_map(start, size, 7)
            uc.mem_write(start, data)
            uc.mem_protect(start,size,perm)
            #print("perm = ", bin(perm))
            perm = 0

        # TODO: add a hook for invalid memory read here
        # write stub that will call the function
        call_opcode = b"\xe8"
        relative_offset = self.function_addr - (self.address_end)
        stub = call_opcode + relative_offset.to_bytes(4, "little")
        self.mem_map(self.address_start, 0x1000)
        uc.mem_write(self.address_start, stub)

        REGS = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",]
        self.mem_map(SCRATCH_ADDR, SCRATCH_SIZE)
        if not brief:
            set_fs(uc, blob['regs']['fs_base'])
        for reg in REGS:
            code = getattr(uni.x86_const, "UC_X86_REG_" + reg.upper())
            uc.reg_write(code, blob['regs'][reg])

        self._patch_got()

    @staticmethod
    def mem_access_hook(emulator: Uc, access: int, address: int, size: int, value: int,
                        self: X86UnicornModel) -> None:
        # operate exclusively on unsigned ints
        if value < 0:
            value = int.from_bytes(value.to_bytes(size, "little", signed=True), "little")

        if hasattr(self.tracer, "mem_access_hook"):
            self.tracer.mem_access_hook(emulator, access, address, size, value, self)

        # hack: using dict keys as an order-preserving set
        predictions = {}
        for predictor in self.predictors:
            predictor.mem_access_hook(emulator, access, address, size, value, self)
            predictions.update({val: None for val in predictor.trace})
            predictor.trace.clear()
        # "correct" value is special, so remove if in predictions set
        predictions.pop(value, None)
        # convert to a list of (addr, pred_value) pairs
        self.prev_predictions.extend((address, val.to_bytes(size, "little"))
                                     if val is not HALT else val
                                     for val in predictions.keys())

    def _use_predictions(self, predictions):
        if predictions:
            if not self.speculative:
                self.branch_count += 1
                self.reorder_buffer = self.SPECULATION_WINDOW
            if len(self.checkpoints) < self.MAX_NESTING:
                self.save_emu_state(self.emulator, predictions, self.reorder_buffer)
            self.emulator.emu_stop()

    @staticmethod
    def syscall_hook(emulator: Uc, self: X86UnicornModel) -> None:
        rax = emulator.reg_read(UC_X86_REG_RAX)
        arg1 = emulator.reg_read(UC_X86_REG_RDI)
        arg2 = emulator.reg_read(UC_X86_REG_RSI)
        arg3 = emulator.reg_read(UC_X86_REG_RDX)
        if rax in (102, 104, 107, 108):
            pass
        elif rax == 158:
            # sys_arch_prctl
            code = arg1
            val = arg2
            if code == 0x1002:  # ARCH_SET_FS
                self._fs = val
                self._rip = emulator.reg_read(UC_X86_REG_RIP)
                emulator.emu_stop()
            # incidentally, 0x3001 is ARCH_CET_STATUS
            emulator.reg_write(UC_X86_REG_RAX, 0)
        elif rax == 12:
            # sys_brk
            brk = arg1
            if brk:
                self.mem_map(self.curbrk, brk - self.curbrk)
                self.curbrk = self._alignup(brk, 0x1000)
            emulator.reg_write(UC_X86_REG_RAX, self.curbrk)
        else:
            emulator.reg_write(UC_X86_REG_RAX, 0)

    def print_mem(self, addr, size):
        assert size % 8 == 0
        stack = bytes(self.emulator.mem_read(addr, size))
        print()
        for x in range(0, size, 32):
            print(hex(x + addr), end="  ")
            for i in range(0, 32, 8):
                if x+i >= size:
                    break
                print(format(int.from_bytes(stack[x+i:x+i+8], 'little'), "016x"), end=" ")
            print()

    def save_emu_state(self, emulator: Uc, addresses: list, reorder_buffer: int) -> None:
        address_state = []
        for (start_address, size) in zip(self.write_start_addresses, self.write_size):
            address_state.append(emulator.mem_read(start_address,size))
        self.checkpoints.append(CheckPoint(address_state,addresses,self.get_stack(),emulator.reg_read(UC_X86_REG_EFLAGS),emulator.context_save(),reorder_buffer))


    def patch_function(self, emulator: Uc, address: int, size: int, fns) -> None:
        fns = self._patches[address]
        if 'mempcpy' in fns:
            dst = emulator.reg_read(UC_X86_REG_RDI)
            src = emulator.reg_read(UC_X86_REG_RSI)
            n = emulator.reg_read(UC_X86_REG_RDX)
            emulator.mem_write(dst, bytes(emulator.mem_read(src, n)))
            self._emulate_return(emulator, dst + n)
        elif 'memcpy' in fns or 'memmove' in fns:
            dst = emulator.reg_read(UC_X86_REG_RDI)
            src = emulator.reg_read(UC_X86_REG_RSI)
            n = emulator.reg_read(UC_X86_REG_RDX)
            emulator.mem_write(dst, bytes(emulator.mem_read(src, n)))
            self._emulate_return(emulator, dst)
        # implementation for memset
        elif 'memset' in fns:
            dst = emulator.reg_read(UC_X86_REG_RDI)
            byte = emulator.reg_read(UC_X86_REG_RSI)
            n = emulator.reg_read(UC_X86_REG_RDX)
            emulator.mem_write(dst, bytes([byte] * n))
            self._emulate_return(emulator, dst)
        elif 'strchrnul' in fns:
            s = emulator.reg_read(UC_X86_REG_RDI)
            n = emulator.reg_read(UC_X86_REG_RSI)
            i=0
            while emulator.mem_read(s+i, 1)[0] != 0:
                if emulator.mem_read(s+i, 1)[0] == n:
                    break
                i=i+1
            self._emulate_return(emulator, s+i)
        elif 'strlen' in fns:
            s = emulator.reg_read(UC_X86_REG_RDI)
            i=0
            while emulator.mem_read(s+i, 1)[0] != 0:
                i=i+1
            self._emulate_return(emulator, int(i))
        elif 'memcmp_ifunc' in fns or 'bcmp' in fns:
            s1 = emulator.reg_read(UC_X86_REG_RDI)
            s2 = emulator.reg_read(UC_X86_REG_RSI)
            n = emulator.reg_read(UC_X86_REG_RDX)
            i=0
            return_value = 0
            while i<n: 
                if emulator.mem_read(s1+i, 1)[0] != emulator.mem_read(s2+i, 1)[0]:
                    return_value = -3
                    break
                i=i+1 
            self._emulate_return(emulator, return_value)

    @staticmethod
    def instruction_hook(emulator: Uc, address: int, size: int, self: X86UnicornModel) -> None:
        self.instruction_count += 1
        if hasattr(self.tracer, "instruction_hook"):
            self.tracer.instruction_hook(emulator, address, size, self)

        if address in self._patches:
            self.patch_function(emulator, address, size, self._patches[address])

    @staticmethod
    def speculate_instruction_hook(emulator: Uc, address: int, size: int, self: X86UnicornModel) -> None:
        '''
        mode_str = ""
        if not self.speculative:
            mode_str = "NORM"
        else:
            mode_str = "SPEC"
        '''
        self.instruction_count += 1
        try:
            inst: capstone.CsInsn = disasm_inst(self.cs, emulator, address, size)
            #print("%s | 0x%x: %s\t%s" %(mode_str, address, inst.mnemonic, inst.op_str))
            capstone_was_able_to_disasm = True
        except StopIteration:
            capstone_was_able_to_disasm = False

        # if the previous instruction had (control flow) predictions,
        # then we can launch speculation now that we know the "correct" target
        if self.prev_predictions:
            predictions = [a for a in self.prev_predictions if a != address]
            self.prev_predictions.clear()
            self._use_predictions(predictions)

        if capstone_was_able_to_disasm and hasattr(self.tracer, "instruction_hook"):
            self.tracer.instruction_hook(emulator, address, size, self)

        try:
            if address in self._patches:
                self.patch_function(emulator, address, size, self._patches[address])
        except:
            emulator.emu_stop() 

        if capstone_was_able_to_disasm:
            # hack: using dict keys as an order-preserving set
            predictions = {}
            for predictor in self.predictors:
                predictor.instruction_hook(emulator, address, size, self)
                predictions.update({addr: None for addr in predictor.trace})
                predictor.trace.clear()
            # convert to a list
            self.prev_predictions.extend(predictions.keys())

        if self.speculative:
            self.reorder_buffer -= 1
            if self.reorder_buffer <= 0 or (capstone_was_able_to_disasm and inst.id in self.SERIALIZING_INSTR):
                emulator.emu_stop()

        self.prev_pc = address

    # handles the return values 
    @staticmethod
    def _emulate_return(emu, val=None):
        if val is not None:
            emu.reg_write(UC_X86_REG_RAX, val)
        rsp = emu.reg_read(UC_X86_REG_RSP)
        raddr = int.from_bytes(emu.mem_read(rsp, 8), "little")
        emu.reg_write(UC_X86_REG_RSP, rsp + 8)
        emu.reg_write(UC_X86_REG_RIP, raddr)

    @staticmethod
    def instruction_invalid(uc: Uc, self: X86UnicornModel) -> None:
        rip = uc.reg_read(UC_X86_REG_RIP)
        segment = next(seg for seg in self._segments if seg[0] <= rip < seg[1])
        if segment[0] not in self._decoders:
            self._decoders[segment[0]] = iced_x86.Decoder(64, emulator.mem_read(segment[0], segment[1] - segment[0]), ip=segment[0])
        decoder = self._decoders[segment[0]]
        decoder.ip = rip
        decoder.position = rip - segment[0]
        instr = decoder.decode()
        rip = emulator.reg_read(UC_X86_REG_RIP)
        print(f"!! INVALID @ {rip:x}  {instr}")
        iinfo = self._iifactory.info(instr)
        for reg in iinfo.used_registers():
            hasval = ''
            regname = ICED_rlookup[reg.register]
            if reg.access in (iced_x86.OpAccess.READ, iced_x86.OpAccess.COND_READ, iced_x86.OpAccess.READ_WRITE, iced_x86.OpAccess.READ_COND_WRITE):
                code = globals().get(f'UC_X86_REG_{regname}')
                if code:
                    rx = emulator.reg_read(code)
                    hasval = f': {hex(rx)}'
            print(' ', format(regname, '<4'), hasval)
        # skip over the instruction
        uc.reg_write(UC_X86_REG_RIP, decoder.rip)
        return True

    @staticmethod
    def mem_access_unmapped_hook(emulator: Uc, access: int, address: int, size: int, value: int, self: X86UnicornModel):
        if self.speculative:
            return
        page = address // 0x1000
        self.mem_map(address, size, 7)
        emulator._hook_exception = None
        if access == uni.UC_MEM_WRITE_UNMAPPED:
            emulator.mem_write(address, (value & (1 << 8 * size) - 1).to_bytes(size, "little"))
        else:
            val = emulator.mem_read(address, size)
        print('BAD MEM @', hex(address), ':', size)
        self.print_state()
        stack = self.get_stack()
        rsp = self.emulator.reg_read(UC_X86_REG_RSP)
        for x in range(min(rsp + 16 * 8, self.STACK) - 8, rsp - 8, -8):
            x -= self.STACK_TOP
            print(hex(x + self.STACK_TOP), format(int.from_bytes(stack[x:x+8], 'little'), "016x"))

    def test_mem_dump(self):
        mem_dump = {}
        for addr_start, addr_end, _ in self.emulator.mem_regions():
            if addr_start == 0x7fff0000: continue # skip stack
            mem_dump[addr_start] = self.emulator.mem_read(addr_start, addr_end - addr_start)
        if self.prev_mem_dump is not None:
            if self.prev_mem_dump != mem_dump:
                print("MEMORY DIFFERS")
                for addr, content in mem_dump.items():
                    for i in range(len(content)):
                        b1 = self.prev_mem_dump[addr][i]
                        b2 = mem_dump[addr][i]
                        if b1 != b2:
                            print(hex(addr+i), hex(b1), hex(b2))
                exit(0)
        self.prev_mem_dump = mem_dump

    # TODO: runs test cases 
    def trace_test_case(self, input_: Input) -> Tuple[Trace, int]:
        self.reset_model()
        self._load_input(input_)
        self.tracer.start_tracing(self, input_) # do this after loading input
        for predictor in self.predictors:
            predictor.start_tracing(self, input_)
        start_time = time.time()
        timed_out = False
        while True:
            if (time.time() - start_time) > TIMEOUT:
                timed_out = True
                break

            try:
                self.emulator.emu_start(self.address_start, self.address_end)
            except UcError as e:
                #print("self.speculative = ",self.speculative)
                #print("len(self.checkpoints) = ",len(self.checkpoints))
                #print("[X86UnicornModel:trace_test_case] %s" % e)
                if not self.speculative and not self.checkpoints:
                    print("print state on error during normal exeution:")
                    self.print_state()
                    stack = self.get_stack()
                    rsp = self.emulator.reg_read(UC_X86_REG_RSP)
                    rsp -= self.STACK_TOP
                    print(format(int.from_bytes(stack[rsp:rsp+8], 'little'), "016x"))
                    LOGGER.error("[X86UnicornModel:trace_test_case] %s" % e)
                    break
            if not self.checkpoints:
                break

            # rollback operation
            while self.checkpoints:
                checkpoint = self.checkpoints[-1]

                # restore registers etc
                self.emulator.context_restore(checkpoint.context)
                # write back flags
                self.emulator.reg_write(UC_X86_REG_EFLAGS, checkpoint.flag)
                # restore memory
                self.emulator.mem_write(self.STACK_TOP, checkpoint.stack)
                for (start, mem) in zip(self.write_start_addresses, checkpoint.address_space):
                    self.emulator.mem_write(start,bytes(mem))

                # take next prediction if any
                try:
                    pred = checkpoint.predictions.pop(0)
                except IndexError:
                    # no more predictions, continue with "correct" execution
                    self.checkpoints.pop()
                    new_addr = self.emulator.reg_read(UC_X86_REG_RIP)
                else:
                    try:
                        addr, data = pred
                    except TypeError:
                        if pred is HALT:
                            # kill current speculative path
                            # and continue with "correct" execution
                            self.checkpoints.pop()
                            continue
                        # pred is a single value, so it's a pc prediction
                        new_addr = pred
                        self.emulator.reg_write(UC_X86_REG_RIP, new_addr)
                    else:
                        # pred was two values, so it's a memory value prediction
                        self.emulator.mem_write(addr, data)
                        new_addr = self.emulator.reg_read(UC_X86_REG_RIP)

                self.address_start = new_addr
                self.speculative = bool(self.checkpoints)
                break

        return self.tracer.get_trace(), self.instruction_count, timed_out

    def get_stack(self) -> bytes:
        return bytes(self.emulator.mem_read(self.STACK_TOP, self.STACK_SIZE))

    def get_registers(self) -> Registers:
        regs = (self.emulator.reg_read(reg) for reg in UNICORN_REGS)
        return Registers(*regs)

    def reset_model(self):
        self.tracer.reset_trace()
        for predictor in self.predictors:
            predictor.reset_trace()
        self.speculative = False
        self.address_start = STUB_ADDR
        self.instruction_count = 0
        self.branch_count = 0
        self.reorder_buffer = 0
        self.checkpoints.clear()
        self.prev_pc = 0
        self.prev_predictions.clear()
        for start, end in self._segments:
            size = end - start
            self.emulator.mem_unmap(start, size)

        self._mapped = set()
        self._segments = set()

        self._import_dumps()

    def _load_input(self, input_: Input):
        # Registers
        for i, value in enumerate(input_.regs):
            # For not specified registers, set them to 0 if we are resetting the
            # state. Otherwise don't set them.
            self.emulator.reg_write(UNICORN_REGS[i], value if value else 0)
        self.emulator.reg_write(UC_X86_REG_EFLAGS, 0x200)

        # Stack. If we are not keeping the state, make sure we are resetting
        # the whole stack.
        stack = input_.stack.rjust(self.STACK_SIZE, b"\x00")
        self.emulator.mem_write(self.STACK - len(stack), stack)

    def print_state(self, oneline: bool = False):
        emulator = self.emulator
        rax = emulator.reg_read(UC_X86_REG_RAX)
        rbx = emulator.reg_read(UC_X86_REG_RBX)
        rcx = emulator.reg_read(UC_X86_REG_RCX)
        rdx = emulator.reg_read(UC_X86_REG_RDX)
        rsi = emulator.reg_read(UC_X86_REG_RSI)
        rdi = emulator.reg_read(UC_X86_REG_RDI)

        r8 = emulator.reg_read(UC_X86_REG_R8)
        r9 = emulator.reg_read(UC_X86_REG_R9)
        r14 = emulator.reg_read(UC_X86_REG_R14)
        r15 = emulator.reg_read(UC_X86_REG_R15)
        fs = emulator.reg_read(UC_X86_REG_FS)
        fsbase = emulator.reg_read(UC_X86_REG_FS_BASE)

        rsp = emulator.reg_read(UC_X86_REG_RSP)
        rbp = emulator.reg_read(UC_X86_REG_RBP)
        rip = emulator.reg_read(UC_X86_REG_RIP)

        xmm0 = emulator.reg_read(UC_X86_REG_XMM0)
        if self.speculative:
            print("error during epeculative execution")
        if not oneline:
            print("\n\nRegisters:")
            print(f"RAX: {rax:x}")
            print(f"RBX: {rbx:x}")
            print(f"RCX: {rcx:x}")
            print(f"RDX: {rdx:x}")
            print(f"RSI: {rsi:x}")
            print(f"RDI: {rdi:x}")
            print()
            print(f" R8: {r8:x}")
            print(f" R9: {r9:x}")
            print(f"R14: {r14:x}")
            print(f"R15: {r15:x}")
            print(f" FS: {fs:x}")
            print(f" FS_BASE: {fsbase:x}")
            print()
            print(f"RSP: {rsp:x}")
            print(f"RBP: {rbp:x}")
            print(f"RIP: {rip:x}")
            print()
            print(f"XMM0: {xmm0:x}")
        else:
            print(f"rax={rax} "
                  f"rbx={rbx} "
                  f"rcx={rcx} "
                  f"rdx={rdx} "
                  f"rsi={rsi} "
                  f"rdi={rdi} "
                  f"fl={emulator.reg_read(UC_X86_REG_EFLAGS):012b}")


def get_tracer() -> X86UnicornTracer:

    if CONF.tracer == "silent-store":
        tracer = {"ss": leakage_models.SilentStoreTracer,
                  "ssi": leakage_models.SilentStoreInitializedOnlyTracer,
                  "ssi0": leakage_models.SilentStore0InitializedOnlyTracer}[CONF.leakage_name]()
    elif CONF.tracer == "register-file-compression":
        tracer = {"rfc": leakage_models.RegisterFileCompressionTracer,
                  "rfc0": leakage_models.RegisterFileCompression0Tracer}[CONF.leakage_name]()
    elif CONF.tracer == "narrow-register-file-compression":
        tracer = {"nrfc": leakage_models.NarrowRegisterFileCompressionTracer}[CONF.leakage_name]()
    elif CONF.tracer == "computation-simplification":
        tracer = {"cst": leakage_models.TrivialComputationSimplificationTracer,
                  "cs": leakage_models.SemiTrivialComputationSimplificationTracer}[CONF.leakage_name]()
    elif CONF.tracer == "narrow-computation-simplification":
        tracer = {"ncs": leakage_models.NarrowComputationSimplificationTracer}[CONF.leakage_name]()
    elif CONF.tracer == "operand-packing":
        tracer = {"op": leakage_models.OperandPackingTracer}[CONF.leakage_name]()
    elif CONF.tracer == "computation-reuse":
        tracer = {"cr": leakage_models.ComputationReuseTracer,
                  "cra": leakage_models.ComputationReuseWithAddressesTracer}[CONF.leakage_name]()
    elif CONF.tracer == "constant-time":
        tracer = {"ct": leakage_models.ConstantTimeTracer}[CONF.leakage_name]()
    elif CONF.tracer == "cache-compression":
        tracer = {"cc-fpc": leakage_models.FPCCacheCompressionTracer,
                  "cc-bdi": leakage_models.BDICacheCompressionTracer}[CONF.leakage_name]()
    elif CONF.tracer == "prefetcher":
        tracer = {"pf-nl": leakage_models.NextLinePrefetchTracer,
                  "pf-stream": leakage_models.StreamPrefetchTracer,
                  "pf-m1": leakage_models.M1PrefetchTracer}[CONF.leakage_name]()
    else:
        raise ConfigException("unknown tracer in config.py")
    return tracer

def get_model(binary_path: str, function_name: str, predictors: list[str]) -> Model:
    if CONF.model == "x86-unicorn":
        model = X86UnicornModel
    else:
        raise ConfigException("unknown model in config.py")

    model = model(binary_path, function_name, predictors)
    return model

def load_predictors(predictors: list[str]):
    if predictors is None:
        return []
    # get predictors directly by name
    pred_models = []
    for predictor in predictors:
        pred_class = getattr(execution_models, predictor)
        pred_models.append(pred_class())
    return pred_models
