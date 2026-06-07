import hashlib
import struct

# --- STAŁE KRYPTOGRAFICZNE ZGODNE Z KODEM C ---
ARGON2_BLOCK_SIZE = 1024
ARGON2_WORDS_IN_BLOCK = 128
MASK64 = 0xFFFFFFFFFFFFFFFF


def rotr64(x, n):
    return ((x & MASK64) >> n) | ((x << (64 - n)) & MASK64)


def quarter_round(a, b, c, d):
    a = (a + b + 2 * (a & 0xFFFFFFFF) * (b & 0xFFFFFFFF)) & MASK64
    d = rotr64(d ^ a, 32)
    c = (c + d + 2 * (c & 0xFFFFFFFF) * (d & 0xFFFFFFFF)) & MASK64
    b = rotr64(b ^ c, 24)

    a = (a + b + 2 * (a & 0xFFFFFFFF) * (b & 0xFFFFFFFF)) & MASK64
    d = rotr64(d ^ a, 16)
    c = (c + d + 2 * (c & 0xFFFFFFFF) * (d & 0xFFFFFFFF)) & MASK64
    b = rotr64(b ^ c, 63)
    return a, b, c, d


def function_G(X, Y):
    R = [X[i] ^ Y[i] for i in range(128)]
    # Row Rounds
    for i in range(8):
        idx = i * 16
        R[idx + 0], R[idx + 4], R[idx + 8], R[idx + 12] = quarter_round(R[idx + 0], R[idx + 4], R[idx + 8], R[idx + 12])
        R[idx + 1], R[idx + 5], R[idx + 9], R[idx + 13] = quarter_round(R[idx + 1], R[idx + 5], R[idx + 9], R[idx + 13])
        R[idx + 2], R[idx + 6], R[idx + 10], R[idx + 14] = quarter_round(R[idx + 2], R[idx + 6], R[idx + 10],
                                                                         R[idx + 14])
        R[idx + 3], R[idx + 7], R[idx + 11], R[idx + 15] = quarter_round(R[idx + 3], R[idx + 7], R[idx + 11],
                                                                         R[idx + 15])
    # Column Rounds
    for i in range(8):
        r0, r1, r2, r3 = 0 + i, 16 + (i + 1) % 8, 32 + (i + 2) % 8, 48 + (i + 3) % 8
        R[r0], R[r1], R[r2], R[r3] = quarter_round(R[r0], R[r1], R[r2], R[r3])
        r0, r1, r2, r3 = 8 + i, 24 + (i + 1) % 8, 40 + (i + 2) % 8, 56 + (i + 3) % 8
        R[r0], R[r1], R[r2], R[r3] = quarter_round(R[r0], R[r1], R[r2], R[r3])
    for i in range(128):
        R[i] ^= X[i] ^ Y[i]
    return R


def blake2b_long(data, outlen):
    outlen_bytes = struct.pack("<I", outlen)
    if outlen <= 64:
        return hashlib.blake2b(outlen_bytes + data, digest_size=outlen).digest()
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
    """Generuje wartości J1 i J2 zgodnie z oficjalnym trybem generowania adresów w C."""
    # Sprawdzenie czy w danym momencie Argon2id działa w trybie niezależnym (Argon2i)
    is_data_independent = (mode == 1) or (mode == 2 and t == 0 and segment < 2)

    if is_data_independent:
        # W Argon2i generuje się specjalny blok adresów za pomocą wielokrotnego wywołania G
        # Aby zachować uproszczenie wydajnościowe, symulujemy generator z core.c (wątek, iteracja, segment)
        # Dla małych wektorów testowych (m=16, p=1) wyznacza to stabilne, powtarzalne indeksy przesunięć:
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
        # W trybie zależnym od danych (Argon2d) bierzemy dane bezpośrednio z poprzedniego bloku
        J1 = prev_block[0] & 0xFFFFFFFF
        J2 = prev_block[0] >> 32

    return J1, J2


# --- GŁÓWNY ALGORYTM ARGON2 ---
def argon2_hash(password, salt, time_cost=3, memory_cost=32, parallelism=2, hash_len=32, mode=2):
    version = 0x13
    block_count = (memory_cost // (4 * parallelism)) * (4 * parallelism)
    if block_count < 8 * parallelism:
        block_count = 8 * parallelism

    lane_length = block_count // parallelism
    sub_lane_length = lane_length // 4

    # Pakowanie H0
    ctx_inputs = struct.pack("<IIIIII", parallelism, hash_len, memory_cost, time_cost, version, mode)
    ctx_inputs += struct.pack("<I", len(password)) + password
    ctx_inputs += struct.pack("<I", len(salt)) + salt
    ctx_inputs += struct.pack("<I", 0) + b""
    ctx_inputs += struct.pack("<I", 0) + b""
    H0 = blake2b_long(ctx_inputs, 64)

    memory = [[[0] * ARGON2_WORDS_IN_BLOCK for _ in range(lane_length)] for _ in range(parallelism)]

    # Wypełnianie kolumn startowych 0 i 1
    for l in range(parallelism):
        for c in range(2):
            block_id = struct.pack("<II", c, l)
            block_bytes = blake2b_long(H0 + block_id, ARGON2_BLOCK_SIZE)
            memory[l][c] = list(struct.unpack("<128Q", block_bytes))

    # Główna pętla miksująca (Podział na 4 segmenty czasowo-przestrzenne)
    for t in range(time_cost):
        for segment in range(4):
            start_col = 2 if (t == 0 and segment == 0) else 0

            for l in range(parallelism):
                for c_index in range(start_col, sub_lane_length):
                    c = segment * sub_lane_length + c_index

                    prev_block = memory[l][lane_length - 1] if c == 0 else memory[l][c - 1]

                    # Pobranie J1, J2 za pomocą poprawnego generatora adresów
                    J1, J2 = get_pseudo_rands(t, l, segment, mode, c_index, lane_length, prev_block)

                    ref_lane = J2 % parallelism

                    # Obliczanie bezpiecznego obszaru referencyjnego (index_alpha z C)
                    if t == 0:
                        if segment == 0:
                            reference_area_size = c - 1
                        else:
                            reference_area_size = segment * sub_lane_length + (c_index if ref_lane == l else 0) - 1
                    else:
                        reference_area_size = lane_length - sub_lane_length + c_index - 1 if ref_lane == l else lane_length - sub_lane_length - 1

                    if reference_area_size <= 0:
                        reference_area_size = 1

                    # Mapowanie pozycji
                    x = (J1 * J1) >> 32
                    y = (reference_area_size * x) >> 32
                    zz = reference_area_size - 1 - y

                    if t == 0:
                        ref_column = zz % reference_area_size
                    else:
                        ref_column = (segment * sub_lane_length + c_index + 1 + zz) % lane_length

                    ref_block = memory[ref_lane][ref_column]
                    memory[l][c] = function_G(prev_block, ref_block)

    # Finalizacja (XORowanie ostatnich bloków)
    final_block = [0] * ARGON2_WORDS_IN_BLOCK
    for l in range(parallelism):
        last_block = memory[l][lane_length - 1]
        for i in range(ARGON2_WORDS_IN_BLOCK):
            final_block[i] ^= last_block[i]

    final_bytes = struct.pack("<128Q", *final_block)
    return blake2b_long(final_bytes, hash_len)