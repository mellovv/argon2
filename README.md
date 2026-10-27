# argon2-py

A pure Python 3 implementation of the **Argon2** password hashing function (winner of the Password Hashing Competition, RFC 9106 / v1.3).

Built from scratch without third-party cryptographic dependencies, focusing on algorithm internals, memory-hard constructions, and side-channel resilience principles.

---

## Features

- **Standard Compliance:** Implements Argon2 specification v1.3.
- **Supported Variants:**
  - `Argon2d`: Data-dependent memory access (optimized against GPU/ASIC attacks, suitable for cryptocurrencies and backend proof-of-work).
  - `Argon2i`: Data-independent memory access (resilient against side-channel cache-timing attacks, ideal for password hashing).
  - `Argon2id`: Hybrid construction (recommended for general use: Argon2i for first pass, Argon2d for subsequent passes).
- **Core Cryptographic Primitives:**
  - G compression function based on ARX (Add, Rotate, XOR) quarter-rounds.
  - Variable-length hash expansion via BLAKE2b chaining (`blake2b_long`).
  - Strict 64-bit integer simulation using bitmasks and bit rotations (`rotr64`).
- **CLI & Benchmarking:**
  - Unix pipe-compliant CLI utility for hashing input streams.
  - Performance and memory allocation benchmark harness.

---

## Project Structure

```text
.
├── core.py      # Core Argon2 algorithm, memory matrix allocation, function G
├── cli.py       # Unix-style CLI with stream input support
└── bench.py     # Determinism, avalanche effect verification, and perf benchmarks
```

---

## Getting Started

No external pip packages required (standard library only).

### Running CLI

To prevent plain-text exposure in process arguments or shell history, provide passwords via standard input pipe:

```bash
echo -n "correcthorsebatterystaple" | python3 cli.py somesalt -id -t 2 -m 12 -p 1 -l 32
```

**Parameters:**
- `salt`: Hashing salt (positional, minimum 8 characters).
- `-d` / `-i` / `-id`: Argon2 variant selection (default: `-i`).
- `-t`: Time cost / number of iterations (default: `3`).
- `-m`: Memory cost exponent 2^N KiB (default: `12` -> 4096 KiB).
- `-p`: Degree of parallelism / lanes (default: `1`).
- `-l`: Output hash length in bytes (default: `32`).

### Running Integrity Tests & Benchmarks

```bash
python3 bench.py
```

This runs:
1. **Correctness verification:** Tests for determinism and bit-level avalanche effect.
2. **Stress benchmark:** Execution timing across scaling memory envelopes (1–4 MiB) and thread configurations.
