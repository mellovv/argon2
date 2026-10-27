import hashlib
import struct

# --- BASIC ARGON2 GEOMETRY PARAMETERS ---
ARGON2_BLOCK_SIZE = 1024  # Each single block in memory is exactly 1024 bytes
ARGON2_WORDS_IN_BLOCK = 128  # 1024 bytes divided into 128 64-bit "words" (128 * 8 bytes)
MASK64 = 0xFFFFFFFFFFFFFFFF  # Mask truncating results to 64 bits (simulating C uint64_t registers)


def rotr64(x, n):
    """
    Bitwise right rotation. Bits shifted out from the right
    re-enter from the left, preventing loss of information.
    """
    return ((x & MASK64) >> n) | ((x << (64 - n)) & MASK64)


def quarter_round(a, b, c, d):
    """
    Core four-word mixer (Quarter-Round) borrowed from BLAKE2b.
    Mixes 4 numbers using the ARX (Add, Rotate, XOR) design.
    """
    # First round of pair mixing
    a = (a + b + 2 * (a & 0xFFFFFFFF) * (b & 0xFFFFFFFF)) & MASK64
    d = rotr64(d ^ a, 32)
    c = (c + d + 2 * (c & 0xFFFFFFFF) * (d & 0xFFFFFFFF)) & MASK64
    b = rotr64(b ^ c, 24)

    # Second round of mixing with Argon2-specific 63-bit rotation at the end
    a = (a + b + 2 * (a & 0xFFFFFFFF) * (b & 0xFFFFFFFF)) & MASK64
    d = rotr64(d ^ a, 16)
    c = (c + d + 2 * (c & 0xFFFFFFFF) * (d & 0xFFFFFFFF)) & MASK64
    b = rotr64(b ^ c, 63)
    return a, b, c, d


def function_G(X, Y):
    """
    Main block compression function (1024 bytes). Arranges data into a matrix,
    then mixes row-wise first, followed by diagonal-wise.
    """
    # Step 1: Initial combination of previous block (X) and reference block (Y)
    R = [X[i] ^ Y[i] for i in range(128)]

    # Step 2: Row-wise mixing (Row Rounds) - 8 passes for each row of the matrix
    for i in range(8):
        idx = i * 16
        R[idx], R[idx + 4], R[idx + 8], R[idx + 12] = quarter_round(R[idx], R[idx + 4], R[idx + 8], R[idx + 12])
        R[idx + 1], R[idx + 5], R[idx + 9], R[idx + 13] = quarter_round(R[idx + 1], R[idx + 5], R[idx + 9], R[idx + 13])
        R[idx + 2], R[idx + 6], R[idx + 10], R[idx + 14] = quarter_round(R[idx + 2], R[idx + 6], R[idx + 10], R[idx + 14])
        R[idx + 3], R[idx + 7], R[idx + 11], R[idx + 15] = quarter_round(R[idx + 3], R[idx + 7], R[idx + 11], R[idx + 15])

    # Step 3: Diagonal mixing (Column Rounds / Diagonal Rounds)
    for i in range(8):
        r0, r1, r2, r3 = 0 + i, 16 + (i + 1) % 8, 32 + (i + 2) % 8, 48 + (i + 3) % 8
        R[r0], R[r1], R[r2], R[r3] = quarter_round(R[r0], R[r1], R[r2], R[r3])
        r0, r1, r2, r3 = 8 + i, 24 + (i + 1) % 8, 40 + (i + 2) % 8, 56 + (i + 3) % 8
        R[r0], R[r1], R[r2], R[r3] = quarter_round(R[r0], R[r1], R[r2], R[r3])

    # Step 4: Final XOR with input data (feed-forward protection)
    for i in range(128):
        R[i] ^= X[i] ^ Y[i]
    return R


def blake2b_long(data, outlen):
    """
    Variable-length extension of BLAKE2b.
    """
    outlen_bytes = struct.pack("<I", outlen)
    if outlen <= 64:
        return hashlib.blake2b(outlen_bytes + data, digest_size=outlen).digest()

    # Chaining digests for outputs longer than 64 bytes
    res = b""
    v = hashlib.blake2b(outlen_bytes + data, digest_size=64).digest()
    res += v[:32]
    while len(res) < outlen - 32:
        v = hashlib.blake2b(v, digest_size=64).digest()
        res += v[:32]
    v = hashlib.blake2b(v, digest_size=64).digest()
    res += v[:outlen - len(res)]
    return res


def get_pseudo_rands(t, l, segment, mode, curr_index, lane_length, prev_block):
    """
    Address generator. Determines where (which coordinates in memory) to fetch
    the reference block for mixing, implementing Argon2d, Argon2i, and Argon2id logic.
    """
    # Check if the algorithm is operating in data-independent mode (Argon2i)
    is_data_independent = (mode == 1) or (mode == 2 and t == 0 and segment < 2)

    if is_data_independent:
        # Mode i: coordinates are calculated purely mathematically from the loop counter
        idx = curr_index + 1
        zero_block = [0] * 128
        input_block = [0] * 128
        input_block[0] = t
        input_block[1] = l
        input_block[2] = segment
        input_block[3] = lane_length
        input_block[4] = idx
        addr_block = function_G(zero_block, input_block)
        J1 = addr_block[idx % 128] & 0xFFFFFFFF
        J2 = addr_block[idx % 128] >> 32
    else:
        # Mode d: coordinates depend directly on memory contents (prev_block)
        J1 = prev_block[0] & 0xFFFFFFFF
        J2 = prev_block[0] >> 32

    return J1, J2


# --- MAIN ARGON2 ALGORITHM ---
def argon2_hash(password, salt, time_cost=3, memory_cost=32, parallelism=2, hash_len=32, mode=2):
    """
    Main Argon2 driver function. Allocates memory, initializes it,
    executes mixing passes, and produces the final hash digest.
    """
    version = 0x13  # Constant denoting official standard version v1.3

    # 1. Calculate total number of memory blocks (must be a multiple of 4 * parallelism)
    block_count = (memory_cost // (4 * parallelism)) * (4 * parallelism)
    if block_count < 8 * parallelism:
        block_count = 8 * parallelism

    lane_length = block_count // parallelism  # Length of a single lane (thread)
    sub_lane_length = lane_length // 4  # Lane is divided into 4 synchronization segments

    # 2. Pack input parameters and generate initial seed block H0
    ctx_inputs = struct.pack("<IIIIII", parallelism, hash_len, memory_cost, time_cost, version, mode)
    ctx_inputs += struct.pack("<I", len(password)) + password
    ctx_inputs += struct.pack("<I", len(salt)) + salt
    ctx_inputs += struct.pack("<I", 0) + b""
    ctx_inputs += struct.pack("<I", 0) + b""
    H0 = blake2b_long(ctx_inputs, 64)

    # 3. Allocate virtual RAM memory matrix (Lanes x Columns x 128 words)
    memory = [[[0] * ARGON2_WORDS_IN_BLOCK for _ in range(lane_length)] for _ in range(parallelism)]

    # 4. Fill initial columns (indices 0 and 1) with unique values derived from H0
    for l in range(parallelism):
        for c in range(2):
            block_id = struct.pack("<II", c, l)
            block_bytes = blake2b_long(H0 + block_id, ARGON2_BLOCK_SIZE)
            memory[l][c] = list(struct.unpack("<128Q", block_bytes))

    # 5. Main mixing loop across time and space
    for t in range(time_cost):
        for segment in range(4):
            # In the first iteration, skip the first two columns (already initialized)
            start_col = 2 if (t == 0 and segment == 0) else 0

            for l in range(parallelism):
                for c_index in range(start_col, sub_lane_length):
                    c = segment * sub_lane_length + c_index

                    # Fetch the block immediately preceding the current one
                    prev_block = memory[l][lane_length - 1] if c == 0 else memory[l][c - 1]

                    # Determine position of the pseudo-random reference block (J1, J2)
                    J1, J2 = get_pseudo_rands(t, l, segment, mode, c_index, lane_length, prev_block)
                    ref_lane = J2 % parallelism

                    # Determine dynamic bounds of the reference memory area (index_alpha from C)
                    if t == 0:
                        if segment == 0:
                            reference_area_size = c - 1
                        else:
                            reference_area_size = segment * sub_lane_length + (c_index if ref_lane == l else 0) - 1
                    else:
                        reference_area_size = lane_length - sub_lane_length + c_index - 1 if ref_lane == l else lane_length - sub_lane_length - 1

                    if reference_area_size <= 0:
                        reference_area_size = 1

                    # Mathematically map pseudo-random values to a specific column index
                    x = (J1 * J1) >> 32
                    y = (reference_area_size * x) >> 32
                    zz = reference_area_size - 1 - y

                    if t == 0:
                        ref_column = zz % reference_area_size
                    else:
                        ref_column = (segment * sub_lane_length + c_index + 1 + zz) % lane_length

                    # Fetch the designated reference block from memory
                    ref_block = memory[ref_lane][ref_column]

                    # Mix previous block with reference block
                    new_block = function_G(prev_block, ref_block)

                    # Argon2 v1.3: overwrite memory in the first iteration,
                    # in subsequent iterations (t > 0), XOR new contents with existing memory cell.
                    if t == 0:
                        memory[l][c] = new_block
                    else:
                        old_block = memory[l][c]
                        memory[l][c] = [old_block[i] ^ new_block[i] for i in range(ARGON2_WORDS_IN_BLOCK)]

    # 6. Finalization: XOR the last blocks from each lane together
    final_block = [0] * ARGON2_WORDS_IN_BLOCK
    for l in range(parallelism):
        last_block = memory[l][lane_length - 1]
        for i in range(ARGON2_WORDS_IN_BLOCK):
            final_block[i] ^= last_block[i]

    # Pack words into bytes and produce the final user digest
    final_bytes = struct.pack("<128Q", *final_block)
    return blake2b_long(final_bytes, hash_len)
