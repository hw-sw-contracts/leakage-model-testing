CF = 0b000000000001
PF = 0b000000000100
AF = 0b000000010000
ZF = 0b000001000000
SF = 0b000010000000
OF = 0b100000000000

CX_FLAG = 0xffff
ECX_FLAG = 0xffffffff
RCX_FLAG = 0xffffffffffffffff

def je(flags, rcx, next_addr, branch_addr,size):
    cond = (flags&ZF != 0)
    return [(cond)*(next_addr+size) + (not cond)*branch_addr,(not cond)*(next_addr+size) + (cond)*branch_addr]

def ja(flags, rcx, next_addr, branch_addr, size):
    cond = (not (flags&ZF) and not (flags&CF))
    return [(cond)*(next_addr+size) + (not cond)*branch_addr,(not cond)*(next_addr+size) + (cond)*branch_addr]

def jae(flags, rcx, next_addr, branch_addr,size):
    cond = (flags&CF == 0)
    return [(cond)*(next_addr+size) + (not cond)*branch_addr,(not cond)*(next_addr+size) + (cond)*branch_addr]

def jb(flags, rcx, next_addr, branch_addr,size):
    cond = (flags&CF != 0)
    return [(cond)*(next_addr+size) + (not cond)*branch_addr,(not cond)*(next_addr+size) + (cond)*branch_addr]

def jbe(flags, rcx, next_addr, branch_addr,size):
    cond = (flags&(ZF|CF) != 0)
    return [(cond)*(next_addr+size) + (not cond)*branch_addr,(not cond)*(next_addr+size) + (cond)*branch_addr]

def jcxz(flags, rcx, next_addr, branch_addr,size):
    cond = (rcx&CX_FLAG == 0)
    return [(cond)*(next_addr+size) + (not cond)*branch_addr,(not cond)*(next_addr+size) + (cond)*branch_addr]

def jecxz(flags, rcx, next_addr, branch_addr,size):
    cond = (rcx&ECX_FLAG == 0)
    return [(cond)*(next_addr+size) + (not cond)*branch_addr,(not cond)*(next_addr+size) + (cond)*branch_addr]

def jrcxz(flags, rcx, next_addr, branch_addr,size):
    cond = (rcx&RCX_FLAG == 0)
    return [(cond)*(next_addr+size) + (not cond)*branch_addr,(not cond)*(next_addr+size) + (cond)*branch_addr]

def jg(flags, rcx, next_addr, branch_addr,size):
    cond = (flags&(ZF) == 0 and flags&(SF|OF) in (SF|OF,0))
    return [(cond)*(next_addr+size) + (not cond)*branch_addr,(not cond)*(next_addr+size) + (cond)*branch_addr]

def jge(flags, rcx, next_addr, branch_addr,size):
    cond = (flags&(SF|OF) in (SF|OF,0))
    return [(cond)*(next_addr+size) + (not cond)*branch_addr,(not cond)*(next_addr+size) + (cond)*branch_addr]

def jl(flags, rcx, next_addr, branch_addr,size):
    cond = (flags&(SF|OF) not in (SF|OF,0))
    return [(cond)*(next_addr+size) + (not cond)*branch_addr,(not cond)*(next_addr+size) + (cond)*branch_addr]

def jle(flags, rcx, next_addr, branch_addr,size):
    cond = ((flags & ZF) != 0 or (flags&(SF|OF) not in (SF|OF,0)))
    return [(cond)*(next_addr+size) + (not cond)*branch_addr,(not cond)*(next_addr+size) + (cond)*branch_addr]

def jne(flags, rcx, next_addr, branch_addr,size):
    cond = (flags&ZF == 0)
    return [(cond)*(next_addr+size) + (not cond)*branch_addr,(not cond)*(next_addr+size) + (cond)*branch_addr]

def jno(flags, rcx, next_addr, branch_addr,size):
    cond = (flags&OF == 0)
    return [(cond)*(next_addr+size) + (not cond)*branch_addr,(not cond)*(next_addr+size) + (cond)*branch_addr]

def jnp(flags, rcx, next_addr, branch_addr,size):
    cond = (flags&PF == 0)
    return [(cond)*(next_addr+size) + (not cond)*branch_addr,(not cond)*(next_addr+size) + (cond)*branch_addr]

def jns(flags, rcx, next_addr, branch_addr,size):
    cond = (flags&SF == 0)
    return [(cond)*(next_addr+size) + (not cond)*branch_addr,(not cond)*(next_addr+size) + (cond)*branch_addr]

def jo(flags, rcx, next_addr, branch_addr,size):
    cond = (flags&OF != 0)
    return [(cond)*(next_addr+size) + (not cond)*branch_addr,(not cond)*(next_addr+size) + (cond)*branch_addr]

def jp(flags, rcx, next_addr, branch_addr,size):
    cond = (flags&PF != 0)
    return [(cond)*(next_addr+size) + (not cond)*branch_addr,(not cond)*(next_addr+size) + (cond)*branch_addr]

def js(flags, rcx, next_addr, branch_addr,size):
    cond = (flags&SF != 0)
    return [(cond)*(next_addr+size) + (not cond)*branch_addr,(not cond)*(next_addr+size) + (cond)*branch_addr]

'''
def je(flags, rcx, next_addr, branch_addr,size):
    cond = (flags&ZF != 0)
    return (not cond)*(next_addr+size) + (cond)*branch_addr

def ja(flags, rcx, next_addr, branch_addr, size):
    cond = (not (flags&ZF) and not (flags&CF))
    return (not cond)*(next_addr+size) + (cond)*branch_addr

def jae(flags, rcx, next_addr, branch_addr,size):
    cond = (flags&CF == 0)
    return (not cond)*(next_addr+size) + (cond)*branch_addr

def jb(flags, rcx, next_addr, branch_addr,size):
    cond = (flags&CF != 0)
    return (not cond)*(next_addr+size) + (cond)*branch_addr

def jbe(flags, rcx, next_addr, branch_addr,size):
    cond = (flags&(ZF|CF) != 0)
    return (not cond)*(next_addr+size) + (cond)*branch_addr

def jcxz(flags, rcx, next_addr, branch_addr,size):
    cond = (rcx&CX_FLAG == 0)
    return (not cond)*(next_addr+size) + (cond)*branch_addr

def jecxz(flags, rcx, next_addr, branch_addr,size):
    cond = (rcx&ECX_FLAG == 0)
    return (not cond)*(next_addr+size) + (cond)*branch_addr

def jrcxz(flags, rcx, next_addr, branch_addr,size):
    cond = (rcx&RCX_FLAG == 0)
    return (not cond)*(next_addr+size) + (cond)*branch_addr

def jg(flags, rcx, next_addr, branch_addr,size):
    cond = (flags&(ZF) == 0 and flags&(SF|OF) in (SF|OF,0))
    return (not cond)*(next_addr+size) + (cond)*branch_addr

def jge(flags, rcx, next_addr, branch_addr,size):
    cond = (flags&(SF|OF) in (SF|OF,0))
    return (not cond)*(next_addr+size) + (cond)*branch_addr

def jl(flags, rcx, next_addr, branch_addr,size):
    cond = (flags&(SF|OF) not in (SF|OF,0))
    return (not cond)*(next_addr+size) + (cond)*branch_addr

def jle(flags, rcx, next_addr, branch_addr,size):
    cond = ((flags & ZF) != 0 or (flags&(SF|OF) not in (SF|OF,0)))
    return (not cond)*(next_addr+size) + (cond)*branch_addr

def jne(flags, rcx, next_addr, branch_addr,size):
    cond = (flags&ZF == 0)
    return (not cond)*(next_addr+size) + (cond)*branch_addr

def jno(flags, rcx, next_addr, branch_addr,size):
    cond = (flags&OF == 0)
    return (not cond)*(next_addr+size) + (cond)*branch_addr

def jnp(flags, rcx, next_addr, branch_addr,size):
    cond = (flags&PF == 0)
    return (not cond)*(next_addr+size) + (cond)*branch_addr

def jns(flags, rcx, next_addr, branch_addr,size):
    cond = (flags&SF == 0)
    return (not cond)*(next_addr+size) + (cond)*branch_addr

def jo(flags, rcx, next_addr, branch_addr,size):
    cond = (flags&OF != 0)
    return (not cond)*(next_addr+size) + (cond)*branch_addr

def jp(flags, rcx, next_addr, branch_addr,size):
    cond = (flags&PF != 0)
    return (not cond)*(next_addr+size) + (cond)*branch_addr

def js(flags, rcx, next_addr, branch_addr,size):
    cond = (flags&SF != 0)
    return (not cond)*(next_addr+size) + (cond)*branch_addr
'''