#!/usr/bin/env python3
import json
import re
import subprocess
import sys
from collections.abc import Mapping
from io import StringIO
from pathlib import Path

import pexpect
import rich.pretty
import ruamel.yaml as yaml
from elftools.elf.elffile import ELFFile, SymbolTableSection
from ruamel.yaml import Representer
from ruamel.yaml.scalarint import HexInt

from config import get_function
gdb = None
output = []

library, algorithm = sys.argv[1:]
function_name = get_function(algorithm, library)

library = Path('targets') / library
outdir = Path('violations_db') / f'{algorithm}-{library.name}' / 'dumps'
outdir.mkdir(parents=True, exist_ok=True)

def sanitize(s):
    return re.sub(r'\x1b\[[^A-Za-z]*[A-Za-z]|\r', r'', s).strip()

def gdbstart():
    global gdb
    gdb = pexpect.spawn('gdb', ['-q'], timeout=2)
    res = gdb.expect([r'\(gdb\)', '<RET> for more'])
    output.append(gdb.before.decode())
    output.append(gdb.after.decode())

def gdbin(cmd):
    gdb.sendline(cmd)
    res = gdb.expect([r'\(gdb\)', '<RET> for more'])
    # output.append('> ' + cmd)
    output.append(gdb.before.decode())
    # output.append('$ ' + str(res))
    # output.append(gdb.after.decode())
    if res:
        return gdbin('')

def gdbquit():
    gdb.sendeof()
    gdb.expect(['will be killed', pexpect.EOF])

gdbstart()
gdbin(f'file {library}')
gdbin(f'b {function_name}')
gdbin('r')
gdbin('info proc mapping')
gdbin('info reg')
gdbin('info reg fs_base')

state = "before"
lines = ''.join(map(sanitize, output)).splitlines()

mappings = []
regs = {}

def unhex(s):
    return int(s.removeprefix("0x"), 16)

for line in lines:
    print("line: {}".format(line))
    if state == "before":
        if "Start Addr" in line:
            state = "mappings"
            continue
    elif state == "mappings":
        try:
            *nums, perms, file = re.match(r'\s*(0x[0-9a-f]+)' * 4 + r'\s*([rwxp-]+)\s*(.*)', line).groups()
            start, end, size, offset = map(unhex, nums)
        except AttributeError:
            state = "regs"
        else:
            mappings.append((start, end, size, offset, perms, file))
    # purposely not elif
    if state == "regs":
        if "q to quit" in line:
            continue
        name, hexval, decval = re.match(r'(\S+)\s*(\S+)\s*(.*)', line).groups()
        val = unhex(hexval)
        regs[name] = val

for start, end, size, offset, perms, file in mappings:
    print(hex(start), hex(end), hex(size), hex(offset), file)
    gdbin(
        ' '.join(
            [
                'dump binary memory',
                str(outdir / f'dump_{start:x}_{end:x}.bin'),
                hex(start),
                hex(end),
            ]
        )
    )
    print(' ', 'wrote', str(outdir / f'dump_{start:x}_{end:x}.bin'))


(outdir / 'dump_data.json').write_text(
    (json.dumps(dict(mappings=mappings, regs=regs), indent=2))
)

nm = subprocess.check_output(
    [*'nm --ifunc-chars=ij -C -n -f sysv'.split(), library], text=True
).splitlines()

dumper = yaml.YAML()

fp = library.open('rb')  # leaving open on purpose
elf = ELFFile(fp)

dumper.representer.add_multi_representer(
    Mapping,
    lambda self, data: Representer.represent_dict(self, data.__dict__),
)

symtab = elf.get_section_by_name('.symtab')
# symtable = {sym.name: HexInt(sym.entry.st_value) for sym in symtab.iter_symbols() if sym.entry.st_value}
symtable = {
    sym.name: dict(addr=HexInt(sym.entry.st_value), entry=sym.entry)
    for sym in symtab.iter_symbols()
    if sym.entry.st_value
}

segments = [dict(header=seg.header) for seg in elf.iter_segments()]
sections = {
    sec.name: dict(addr=HexInt(sec.header.sh_addr), header=sec.header)
    for sec in elf.iter_sections()
}

relocations = []
for sec in elf.iter_sections('SHT_RELA'):
    for entry in sec.iter_relocations():
        relocations.append(
            dict(
                addr=HexInt(entry['r_offset']),
                dest=HexInt(entry['r_addend']),
                entry=entry.entry,
            )
        )

elf_info = dict(
    segments=segments, sections=sections, relocations=relocations, symtable=symtable
)

with (outdir / 'elf_info.yaml').open('w') as fp:
    dumper.dump(elf_info, stream=fp)
# rich.pretty.install()
