from unicorn.x86_const import *

SCRATCH_ADDR = 0x80000
SCRATCH_SIZE = 0x1000

SEGMENT_ADDR = 0x5000
SEGMENT_SIZE = 0x1000


FSMSR = 0xC0000100
GSMSR = 0xC0000101

def set_msr(uc, msr, value, scratch=SCRATCH_ADDR):
    '''
    set the given model-specific register (MSR) to the given value.
    this will clobber some memory at the given scratch address, as it emits some code.
    '''
    # save clobbered registers
    orax = uc.reg_read(UC_X86_REG_RAX)
    ordx = uc.reg_read(UC_X86_REG_RDX)
    orcx = uc.reg_read(UC_X86_REG_RCX)
    orip = uc.reg_read(UC_X86_REG_RIP)

    # x86: wrmsr
    buf = b'\x0f\x30'
    uc.mem_write(scratch, buf)
    uc.reg_write(UC_X86_REG_RAX, value & 0xFFFFFFFF)
    uc.reg_write(UC_X86_REG_RDX, (value >> 32) & 0xFFFFFFFF)
    uc.reg_write(UC_X86_REG_RCX, msr & 0xFFFFFFFF)
    uc.emu_start(scratch, scratch+len(buf), count=1)
    # uc.reg_write(UC_X86_REG_RIP, scratch)

    # restore clobbered registers
    uc.reg_write(UC_X86_REG_RAX, orax)
    uc.reg_write(UC_X86_REG_RDX, ordx)
    uc.reg_write(UC_X86_REG_RCX, orcx)
    uc.reg_write(UC_X86_REG_RIP, orip)


def set_fs(uc, addr):
    '''
    set the FS.base hidden descriptor-register field to the given address.
    this enables referencing the fs segment on x86-64.
    '''
    return set_msr(uc, FSMSR, addr)


def get_fs(uc):
    '''
    fetch the FS.base hidden descriptor-register field.
    '''
    return get_msr(uc, FSMSR)
