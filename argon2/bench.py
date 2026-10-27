import time
from core import argon2_hash



# 1. LOGICAL CORRECTNESS TEST
def start_initial_tests():
    print("--- RUNNING CORRECTNESS TESTS ---")

    # Test data: base password, slightly modified password (d -> D), and salt
    pwd1 = b"password"
    pwd2 = b"passworD"
    salt = b"somesalt"

    # Lightweight configuration for instantaneous logical tests
    t_cost = 2
    m_cost = 16
    parallelism = 1
    hash_len = 32
    mode = 2  # 2 = Argon2id hybrid mode

    print("Computing test hash...")
    try:
        # Run 1: Generate initial hash for password "password"
        hash1 = argon2_hash(pwd1, salt, t_cost, m_cost, parallelism, hash_len, mode).hex()

        # Run 2: Generate hash for the exact same password (verify determinism/repeatability)
        hash1_repeat = argon2_hash(pwd1, salt, t_cost, m_cost, parallelism, hash_len, mode).hex()

        # Run 3: Generate hash for modified password (verify avalanche effect)
        hash2 = argon2_hash(pwd2, salt, t_cost, m_cost, parallelism, hash_len, mode).hex()

        print(f"Hash 1 (password: 'password'): {hash1}")
        print(f"Hash 2 (password: 'password'): {hash1_repeat}")
        print(f"Hash 3 (password: 'passworD'): {hash2}")

        # Determinism
        if hash1 != hash1_repeat:
            print("ERROR: Algorithm is not deterministic! (Returns different results for the same password)")
            return False

        # Avalanche effect
        if hash1 == hash2:
            print("ERROR: Lack of avalanche effect! Password modification did not change the result.")
            return False

        print("✅ SUCCESS: Algorithm is stable, deterministic, and correctly mixes bits.")
        return True

    except Exception as e:
        print(f"Execution error detected in implementation: {e}")
        import traceback
        traceback.print_exc()
        return False

# 2. PERFORMANCE BENCHMARK
def start_benchmark():
    """
    Measures algorithm execution time across different variants (d, i, id),
    scaling allocated memory sizes, and thread counts.
    """
    print("\n--- RUNNING PERFORMANCE BENCHMARK ---")
    t_cost = 3  # Time cost iterations
    hash_len = 16  # Expected output length in bytes

    # Prepare data structures (equivalent to memset from original benchmark.c)
    pwd_array = b'\x00' * 16
    salt_array = b'\x01' * 16

    # Define modes and thread configurations to test
    types = {0: "Argon2d", 1: "Argon2i", 2: "Argon2id"}
    thread_test = [1, 2, 4]

    # Safe RAM allocation bounds for pure Python interpreter
    m_cost = 1 << 10  # Starting point: 1024 KiB (1 MiB)
    max_m_cost = 1 << 12  # Upper bound: 4096 KiB (4 MiB)

    # Main loop doubling memory at each step
    while m_cost <= max_m_cost:
        for thread_n in thread_test:
            run_time = 0.0
            for type_id, type_name in types.items():
                # Start high-precision system timer
                start_time = time.perf_counter()

                try:
                    # Benchmark call to the hashing function
                    argon2_hash(
                        password=pwd_array,
                        salt=salt_array,
                        time_cost=t_cost,
                        memory_cost=m_cost,
                        parallelism=thread_n,
                        hash_len=hash_len,
                        mode=type_id
                    )
                except Exception:
                    # If a given configuration raises an error (e.g. insufficient memory for 4 threads), skip it
                    continue

                # Stop timer and calculate elapsed time in milliseconds
                stop_time = time.perf_counter()
                delta_time = stop_time - start_time
                run_time += delta_time

                print(
                    f"{type_name} {t_cost} iterations | {m_cost >> 10} MiB | {thread_n} threads: {delta_time * 1000:.2f} ms")

            print(f"Total time for parameter set: {run_time:.4f} seconds\n")

        # Proceed to next memory level (equivalent to m_cost *= 2 in C)
        m_cost *= 2


if __name__ == "__main__":
    # Step 1: Verification of mathematical correctness of the algorithm
    code_is_stable = start_initial_tests()

    # Step 2: If tests pass successfully, run stress benchmark
    if code_is_stable:
        start_benchmark()
