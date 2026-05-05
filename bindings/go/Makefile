# Build orchestration for the eth-historian Go bindings.
#
# `go build` / `go test` need the Rust static library to be present
# under target/release, so always run `make build-rust` first (or just
# `make test`, which depends on it).

.PHONY: all
all: test

.PHONY: build-rust
build-rust:
	cargo build --release

.PHONY: test
test: build-rust
	go test -v ./...

.PHONY: clean
clean:
	cargo clean
	rm -f *.test

.PHONY: bench
bench: build-rust
	go test -bench=. -benchmem ./...
