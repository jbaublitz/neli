#!/bin/bash

mkdir cov 

LLVM_PROFILE_FILE="cov/neli-%m.profraw" RUSTFLAGS="-C instrument-coverage" cargo test >/dev/null

cd cov

if [ -z "$1" ]; then
	echo "Defaulting to summary"
	llvm-profdata merge -sparse neli-*.profraw -o neli.profdata
	llvm-cov report \
		--object $(RUSTFLAGS="-C instrument-coverage" cargo test \
			--tests \
			--no-run \
			--message-format=json \
			| jq -r "select(.profile.test == true) | .filenames[]") \
		--instr-profile=neli.profdata \
		--summary-only \
		--ignore-filename-regex="rustc|.cargo/registry"
elif [ "$1" = "full" ]; then
	llvm-profdata merge -sparse neli-*.profraw -o neli.profdata
	llvm-cov show \
		-Xdemangler=rustfilt \
		--show-line-counts-or-regions \
		--object $(RUSTFLAGS="-C instrument-coverage" cargo test \
			--tests \
			--no-run \
			--message-format=json \
			| jq -r "select(.profile.test == true) | .filenames[]") \
		--instr-profile=neli.profdata \
		--ignore-filename-regex="rustc|.cargo/registry"
fi

cd - >/dev/null
rm -rf cov
