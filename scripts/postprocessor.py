#!/usr/bin/env python3
import sys
import time
from pathlib import Path
from symbolizer import symbolize, cmd
from collections import defaultdict
from prettytable import PrettyTable, MARKDOWN
from argparse import ArgumentParser

def get_binary_path(violations_dir):
	binaries = ["libsodium", "nacl", "openssl"]
	for binary in binaries:
		if binary in violations_dir:
			return "targets/" + binary
	raise Exception("Please specify the binary path with `-b` options")

def main():
	parser = ArgumentParser()
	parser.add_argument(
		"violations_dir",
		type=str,
		help="Directory with violations. It should be something like violations_db/algorithm-library/leakage_model"
	)
	parser.add_argument(
		"-m", "--markdown",
		action="store_true",
		help="Print table in markdown syntax"
	)
	parser.add_argument(
		"--pcs",
		action="store_true",
		help="Show PCs, instead of just lines"
	)
	parser.add_argument(
		"-b", "--binary",
		type=str,
		help="Binary path"
	)
	args = parser.parse_args()

	binary = args.binary if args.binary else get_binary_path(args.violations_dir)
	path = Path(args.violations_dir)

	count = 0
	time_start = time.time()
	pcs_count = defaultdict(lambda: 0)
	for violation_dir in path.glob("*"):
		# Get two trace files
		trace_files = list(violation_dir.glob("*_trace"))
		if len(trace_files) < 2:
			raise Exception(f"Violation dir {violation_dir} has less than 2 ({len(trace_files)}) trace files")

		# Get differences of traces
		output = cmd(["diff", str(trace_files[0]), str(trace_files[1])]).splitlines()

		# Count pcs
		def get_pc(line):
			return line.split()[1]
		def is_valid(line):
			return "0x" in line
		for line in output:
			if is_valid(line):
				pcs_count[get_pc(line)] += 1
		count += 1

	print(f"Read {count} violations in {time.time() - time_start:.2f}s")
	assert count

	# Symbolice pcs
	time_start = time.time()
	lines = symbolize(pcs_count.keys(), binary)
	assert len(lines) == len(pcs_count)
	if args.markdown:
		for i in range(len(lines)):
			# Replace references to my local src to links to github
			lines[i] = lines[i].replace(
				"/home/david.mateos/Desktop/imdea/pandora_fuzzing_dev/revizor/targets/libsodium-1.0.18/",
				"https://github.com/jedisct1/libsodium/blob/1.0.18-RELEASE/"
			).replace(
				"/home/david.mateos/Desktop/imdea/pandora_fuzzing_dev/revizor/targets/openssl-3.0.5/",
				"https://github.com/openssl/openssl/blob/openssl-3.0.5/"
			)
			# Replace line number format :123 with #L123
			lines[i] = "#L".join(lines[i].rsplit(":", 1))
			# Enclose symbol (first word) in ``
			lines[i] = "`" + "` ".join(lines[i].split(" ", 1))
	print(f"Symbolized {len(pcs_count)} unique pcs in {time.time() - time_start:.2f}s")

	if args.pcs:
		table = PrettyTable(["Id", "Count", "PC", "Line"])
		# Associate each PC with its src before sorting, and then sort by count
		pc_count_src = zip(pcs_count.items(), lines)
		for i, ((pc, count), src) in enumerate(sorted(pc_count_src, key=lambda item: item[0][1], reverse=True)):
			table.add_row([i+1, count, pc, src])
		table.align["PC"] = "c"

	else:
		# Count occurrences of each line
		counter = defaultdict(lambda: 0)
		for i, pc in enumerate(pcs_count.keys()):
			counter[lines[i]] += pcs_count[pc]
		print(f"Result: {len(counter)} unique lines\n")

		table = PrettyTable(["Id", "Count", "Line"])
		for i, (src, count) in enumerate(sorted(counter.items(), key=lambda item: item[1], reverse=True)):
			table.add_row([i+1, count, src])

	# Print table
	if args.markdown:
		table.set_style(MARKDOWN)
	table.align["Count"] = "r"
	table.align["Line"] = "l"
	print(table)


if __name__ == "__main__":
	main()

# output=""
# for violation in `ls $dir`; do
# 	# output="$output`diff $dir/$violation/0_trace $dir/$violation/1_trace`"
# 	output="$output\n`diff $dir/$violation/0_trace $dir/$violation/1_trace | ./scripts/symbolizer.py $binary | grep '|' | cut -d '|' -f 2`"
# done

# echo -e $output | sort | uniq -c
