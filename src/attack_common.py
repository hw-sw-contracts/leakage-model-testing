import hashlib

def md5_file(path):
	with open(path, "rb") as f:
		return hashlib.md5(f.read()).hexdigest()

def check_correct_file(path):
	md5 = md5_file(path)
	correct_md5 = {
		"targets/libsodium": "c4bf262bda50bdfc83ce53fe97053f98",
		"targets/openssl": "d36a724efaa192e479cc805a61596b2d",
	}[path]
	if md5 != correct_md5:
		raise Exception(f"MD5 of `{path}`, found {md5}, expected {correct_md5}."
						 "It might be needed to change some hardcoded offsets.")

def xor(b1, b2):
	return bytearray([b1[i] ^ b2[i] for i in range(len(b1))])

def xor_byte(b1, byte):
	return xor(b1, [byte]*len(b1))

def pairwise(iterable):
	"s -> (s0, s1), (s2, s3), (s4, s5), ..."
	a = iter(iterable)
	return zip(a, a)

def hexspaces(s):
	return " ".join(b1 + b2 for b1, b2 in pairwise(s.hex()))

def hexspaces_known_pos(s, known_pos):
	return " ".join(b1 + b2 if i in known_pos else "??" for i, (b1, b2) in enumerate(pairwise(s.hex())))

def hexspaces_unknown_pos(s, unknown_pos):
	return " ".join(b1 + b2 if i not in unknown_pos else "??" for i, (b1, b2) in enumerate(pairwise(s.hex())))