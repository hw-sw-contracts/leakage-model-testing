import io
from elftools.elf.elffile import ELFFile, SymbolTableSection
from elftools.elf.constants import P_FLAGS
from typing import List
from unicorn import UC_PROT_READ, UC_PROT_EXEC, UC_PROT_WRITE, UC_PROT_NONE

class ElfParser:
	path: str
	elf: ELFFile

	def __init__(self, binary_path):
		self.path = binary_path
		with open(binary_path, 'rb') as f:
			fstream = io.BytesIO(f.read())
		self.elf = ELFFile(fstream)
		if self.elf.elfclass != 64:
			raise Exception("Elf file must be 64 bits")
		if self.elf["e_type"] != "ET_EXEC":
			raise Exception("Elf file must be statically linked and not PIE")

	def resolve_symbol(self, symbol_name):
		symbol_tables = (sec for sec in self.elf.iter_sections() if isinstance(sec, SymbolTableSection))
		for sec in symbol_tables:
			syms = sec.get_symbol_by_name(symbol_name)
			if syms:
				sym = syms[0]
				return sym["st_value"]
		raise Exception(f"Failed to find symbol '{symbol_name}' in binary '{self.path}'")

	@staticmethod
	def _flags_to_unicorn_perms(flags):
		perms = UC_PROT_NONE
		if flags & P_FLAGS.PF_R:
			perms |= UC_PROT_READ
		if flags & P_FLAGS.PF_W:
			perms |= UC_PROT_WRITE
		if flags & P_FLAGS.PF_X:
			perms |= UC_PROT_EXEC
		return perms

	def iter_load_segments(self):
		for seg in self.elf.iter_segments("PT_LOAD"):
			header = seg.header
			perms = self._flags_to_unicorn_perms(header.p_flags)
			seg.stream.seek(header.p_offset)
			data = seg.stream.read(header.p_filesz)
			yield header.p_vaddr, header.p_memsz, perms, data

	def iter_blank_sections(self):
		for seg in self.elf.iter_sections("SHT_NOBITS"):
			header = seg.header
			perms = self._flags_to_unicorn_perms(header.sh_flags)
			yield header.sh_addr, header.sh_size, perms
