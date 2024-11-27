#!/usr/bin/env python3
import subprocess
import sys
import argparse

def cmd(args):
	return subprocess.run(args, stdout=subprocess.PIPE).stdout.decode()

def is_valid(line):
	return line.startswith("0x") or line.startswith("<") or line.startswith(">")

def get_pc(line):
	words = line.split()
	return words[0] if words[0] != ">" and words[0] != "<" else words[1]

def symbolize(trace_lines, binary):
	pcs = [get_pc(line) for line in trace_lines if is_valid(line)]
	output = cmd(["addr2line", "-f", "-e", binary, *pcs]).splitlines()
	info = {pc: (output[2*i], output[2*i+1]) for i, pc in enumerate(pcs)}

	result=[]
	for line in trace_lines:
		if is_valid(line):
			pc = get_pc(line)
			function, src = info[pc]
			line_result = f"{function} at {src}"
		else:
			line_result = ""
		result.append(line_result)
	return result

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument(
		"binary_path",
		type=str
	)
	parser.add_argument(
		"trace_file",
		type=argparse.FileType("r"),
		nargs="?",
		default=sys.stdin
	)
	args = parser.parse_args()

	trace_lines = args.trace_file.read().splitlines()
	result_lines = symbolize(trace_lines, args.binary_path)
	for i in range(len(trace_lines)):
		info = "| " + result_lines[i] if result_lines[i] else ""
		print(trace_lines[i], info)

if __name__ == "__main__":
	main()