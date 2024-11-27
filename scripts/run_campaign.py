#!/usr/bin/env python3
import os
import itertools

def main():
	os.system("mkdir -p violations")
	os.system("mkdir -p nohup")
	os.system("mkdir -p confs")

	conf_template = """
algorithm: "{}"
library: "{}"
check_results: false
keep_state_of_first_input: false
verbose_leak: false
tracer: "{}"
tracer_options:
{}
"""
	experiments = [
		("salsa", "libsodium", "ssi"),
		("salsa", "libsodium", "rfc"),
		("salsa", "libsodium", "nrfc"),
		("salsa", "libsodium", "cst"),
		("salsa", "libsodium", "ncs"),
		("salsa", "libsodium", "op"),
		("salsa", "libsodium", "cra"),
		("sha512", "libsodium", "ncs"),
		("stream_xor", "libsodium", "ssi0"),
		("stream_xor", "libsodium", "rfc"),
		("stream_xor", "libsodium", "nrfc"),
		("stream_xor", "libsodium", "ncs"),
		("auth", "libsodium", "ncs"),
		("x25519", "libsodium", "ncs"),
		("x25519", "libsodium", "op"),
		("salsa", "nacl", "ssi"),
		("salsa", "nacl", "ncs"),
		("salsa", "nacl", "cr"),
		("sha512", "nacl", "ncs"),
		("poly1305", "nacl", "ncs"),
		("poly1305", "nacl", "cra"),
		("stream_xor", "nacl", "ncs"),
		("auth", "nacl", "ncs"),
		("aes_enc", "openssl", "ncs"),
	]
	tracers = {
		"ssi": ("silent-store", "  only_initialized_memory: true\n  restrict_values_to_check: null\n"),
		"ssi0": ("silent-store", "  only_initialized_memory: true\n  restrict_values_to_check: [0]\n"),
		"rfc": ("register-file-compression", "  restrict_values_to_check: null\n"),
		"nrfc": ("narrow-register-file-compression", "  same_register_allowed: true\n"),
		"cst": ("computation-simplification", "  only_trivial_ops: true\n"),
		"ncs": ("narrow-computation-simplification", "  null"),
		"op": ("operand-packing", "  reservation_update_unit_size: 50\n"),
		"cr": ("computation-reuse", "  reuse_buffers_size: 500\n  n_entries_per_pc: 4\n  reuse_loads: true\n  reuse_addr_calc: false\n"),
		"cra": ("computation-reuse", "  reuse_buffers_size: 500\n  n_entries_per_pc: 4\n  reuse_loads: true\n  reuse_addr_calc: true\n"),
	}

	cores_it = itertools.cycle(os.sched_getaffinity(0))
	for algorithm, library, tracer_codename in experiments:
		codename = f"{algorithm}_{library}_{tracer_codename}"
		violations_path = f"violations/{codename}"
		output_path = f"nohup/{codename}"
		conf_path = f"confs/{codename}"
		tracer, tracer_options = tracers[tracer_codename]
		conf = conf_template.format(algorithm, library, tracer, tracer_options)
		with open(conf_path, "w") as f:
			f.write(conf)
		core = next(cores_it)

		num_inputs = 50 if algorithm not in ["curve25519", "x25519"] else 2
		os.system(f"mkdir -p {violations_path}")
		os.system(f"nohup ./src/cli.py -n 1000000000 --nonstop -c {conf_path} -w {violations_path} --cpu {core} -i {num_inputs} > {output_path} &")
		print(f"Launched {codename} on core {core}")

if __name__ == "__main__":
	main()
