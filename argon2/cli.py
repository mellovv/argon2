import sys
import argparse
from core import argon2_hash


def main():
    # 1. Initialize command-line argument parser
    parser = argparse.ArgumentParser(description="Argon2 in Python")

    # Salt is the only positional argument (required)
    parser.add_argument("salt", help="Salt for hashing (minimum 8 characters)")

    # 2. Create mutually exclusive group for algorithm mode selection
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-i", action="store_const", dest="mode", const=1, help="Use Argon2i (default)")
    group.add_argument("-d", action="store_const", dest="mode", const=0, help="Use Argon2d")
    group.add_argument("-id", action="store_const", dest="mode", const=2, help="Use Argon2id")

    # If no flag is specified, default to Argon2i (mode=1)
    parser.set_defaults(mode=1)

    # 3. Define optional configuration parameters (flags -t, -m, -p, -l)
    parser.add_argument("-t", type=int, default=3, help="Number of iterations / time cost (default: 3)")
    parser.add_argument("-m", type=int, default=12, help="Memory cost exponent 2^N KiB (default: 12, i.e., 4096 KiB)")
    parser.add_argument("-p", type=int, default=1, help="Parallelism / thread count (default: 1)")
    parser.add_argument("-l", type=int, default=32, dest="l", help="Target hash length in bytes (default: 32)")

    # Parse command-line arguments into 'args' object
    args = parser.parse_args()

    # 4. Security check: verify password is piped via stdin ('|')
    # sys.stdin.isatty() returns True if the program is run directly and waiting for keyboard input
    if sys.stdin.isatty():
        print("ERROR: Provide password via standard input pipe!")
        print("Example: echo -n 'password' | python cli.py somesalt -t 2 -m 16 -p 4 -l 24")
        sys.exit(1)

    # 5. Read input from stdin pipe and convert types
    pwd = sys.stdin.read().encode('utf-8')  # Read password from stream and convert to bytes
    salt = args.salt.encode('utf-8')  # Convert text salt to bytes

    # Calculate memory cost using bit shifting (powers of two)
    m_cost = 1 << args.m  # E.g. 1 << 12 gives 4096 KiB (4 MiB)

    # 6. Call main cryptographic function from core.py
    hash_bytes = argon2_hash(
        password=pwd,
        salt=salt,
        time_cost=args.t,
        memory_cost=m_cost,
        parallelism=args.p,
        hash_len=args.l,
        mode=args.mode
    )

    # 7. Dictionary mapping numeric identifiers to readable variant names
    mode_name = {0: "Argon2d", 1: "Argon2i", 2: "Argon2id"}[args.mode]

    # 8. Display final report formatted to match the official C application
    print(f"Type:           {mode_name}")
    print(f"Iterations:     {args.t}")
    print(f"Memory:         {m_cost} KiB")
    print(f"Parallelism:    {args.p}")
    print(f"Hash:           {hash_bytes.hex()}")


if __name__ == "__main__":
    main()
