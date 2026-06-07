import hashlib
import struct

# --- PODSTAWOWE PARAMETRY GEOMETRII ARGON2 ---
ARGON2_BLOCK_SIZE = 1024  # Każdy pojedynczy blok w pamięci ma dokładnie 1024 bajty
ARGON2_WORDS_IN_BLOCK = 128  # 1024 bajty dzielimy na 128 "słów" 64-bitowych (128 * 8 bajtów)
MASK64 = 0xFFFFFFFFFFFFFFFF  # Maska obcinająca wyniki do 64 bitów (symulacja rejestrów uint64_t z C)


def rotr64(x, n):
    """
    Rotacja bitowa w prawo. Bity, które wypadają z prawej strony,
    wracają na początek z lewej strony, zapobiegając utracie informacji.
    """
    return ((x & MASK64) >> n) | ((x << (64 - n)) & MASK64)


def quarter_round(a, b, c, d):
    """
    Podstawowy mikser czterech słów (Quarter-Round) zapożyczony z BLAKE2b.
    Miesza ze sobą 4 liczby za pomocą potrójnej operacji ARX:
    Add, Rotate i XOR.
    """
    # Pierwsza runda mieszania par
    a = (a + b + 2 * (a & 0xFFFFFFFF) * (b & 0xFFFFFFFF)) & MASK64
    d = rotr64(d ^ a, 32)
    c = (c + d + 2 * (c & 0xFFFFFFFF) * (d & 0xFFFFFFFF)) & MASK64
    b = rotr64(b ^ c, 24)

    # Druga runda mieszania z unikalną dla Argon2 rotacją o 63 bity na końcu
    a = (a + b + 2 * (a & 0xFFFFFFFF) * (b & 0xFFFFFFFF)) & MASK64
    d = rotr64(d ^ a, 16)
    c = (c + d + 2 * (c & 0xFFFFFFFF) * (d & 0xFFFFFFFF)) & MASK64
    b = rotr64(b ^ c, 63)
    return a, b, c, d


def function_G(X, Y):
    """
    Główna funkcja kompresji bloku (1024 bajty). Układa dane w macierz,
    następnie miesza je najpierw całymi wierszami, a potem przekątnymi.
    """
    # Krok 1: Wstępne połączenie bloku poprzedniego (X) i referencyjnego (Y)
    R = [X[i] ^ Y[i] for i in range(128)]

    # Krok 2: Mieszanie wierszami (Row Rounds) - 8 powtórzeń dla każdego wiersza macierzy
    for i in range(8):
        idx = i * 16
        R[idx], R[idx + 4], R[idx + 8], R[idx + 12] = quarter_round(R[idx], R[idx + 4], R[idx + 8], R[idx + 12])
        R[idx + 1], R[idx + 5], R[idx + 9], R[idx + 13] = quarter_round(R[idx + 1], R[idx + 5], R[idx + 9], R[idx + 13])
        R[idx + 2], R[idx + 6], R[idx + 10], R[idx + 14] = quarter_round(R[idx + 2], R[idx + 6], R[idx + 10], R[idx + 14])
        R[idx + 3], R[idx + 7], R[idx + 11], R[idx + 15] = quarter_round(R[idx + 3], R[idx + 7], R[idx + 11], R[idx + 15])

    # Krok 3: Mieszanie przekątnymi (Column Rounds / Diagonal Rounds)
    for i in range(8):
        r0, r1, r2, r3 = 0 + i, 16 + (i + 1) % 8, 32 + (i + 2) % 8, 48 + (i + 3) % 8
        R[r0], R[r1], R[r2], R[r3] = quarter_round(R[r0], R[r1], R[r2], R[r3])
        r0, r1, r2, r3 = 8 + i, 24 + (i + 1) % 8, 40 + (i + 2) % 8, 56 + (i + 3) % 8
        R[r0], R[r1], R[r2], R[r3] = quarter_round(R[r0], R[r1], R[r2], R[r3])

    # Krok 4: Końcowy XOR z danymi wejściowymi (zabezpieczenie feed-forward)
    for i in range(128):
        R[i] ^= X[i] ^ Y[i]
    return R


def blake2b_long(data, outlen):
    """
    Rozszerzona wersja BLAKE2b.
    """
    outlen_bytes = struct.pack("<I", outlen)
    if outlen <= 64:
        return hashlib.blake2b(outlen_bytes + data, digest_size=outlen).digest()

    # Tworzenie łańcucha skrótów (chaining) dla wyników dłuższych niż 64 bajty
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
    Generator adresów. Ustala skąd (z której współrzędnej w pamięci) pobrać
    blok referencyjny do wymieszania, realizując logikę trybów d, i oraz id.
    """
    # Sprawdzamy czy algorytm w tym momencie działa niezależnie od danych (tryb Argon2i)
    is_data_independent = (mode == 1) or (mode == 2 and t == 0 and segment < 2)

    if is_data_independent:
        # Tryb i: współrzędne obliczane są czysto matematycznie z licznika pętli
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
        # Tryb d: współrzędne zależą bezpośrednio od zawartości pamięci (prev_block)
        J1 = prev_block[0] & 0xFFFFFFFF
        J2 = prev_block[0] >> 32

    return J1, J2


# --- GŁÓWNY ALGORYTM ARGON2 ---
def argon2_hash(password, salt, time_cost=3, memory_cost=32, parallelism=2, hash_len=32, mode=2):
    """
    Główna funkcja sterująca Argon2. Rezerwuje pamięć, inicjalizuje ją,
    przeprowadza pętle mieszania i wypluwa ostateczny skrót.
    """
    version = 0x13  # Stała oznaczająca oficjalną wersję standardu v1.3

    # 1. Obliczanie całkowitej liczby bloków pamięci (musi pasować do liczby wątków)
    block_count = (memory_cost // (4 * parallelism)) * (4 * parallelism)
    if block_count < 8 * parallelism:
        block_count = 8 * parallelism

    lane_length = block_count // parallelism  # Długość pojedynczej ścieżki (wątku)
    sub_lane_length = lane_length // 4  # Ścieżka dzielona jest na 4 segmenty synchronizacji

    # 2. Pakowanie parametrów wejściowych i generowanie pierwszego bloku startowego H0
    ctx_inputs = struct.pack("<IIIIII", parallelism, hash_len, memory_cost, time_cost, version, mode)
    ctx_inputs += struct.pack("<I", len(password)) + password
    ctx_inputs += struct.pack("<I", len(salt)) + salt
    ctx_inputs += struct.pack("<I", 0) + b""
    ctx_inputs += struct.pack("<I", 0) + b""
    H0 = blake2b_long(ctx_inputs, 64)

    # 3. Alokacja wirtualnej matrycy pamięci RAM (Wątki x Kolumny x 128 słów)
    memory = [[[0] * ARGON2_WORDS_IN_BLOCK for _ in range(lane_length)] for _ in range(parallelism)]

    # 4. Wypełnianie kolumn startowych (indeks 0 i 1) unikalnymi wartościami z H0
    for l in range(parallelism):
        for c in range(2):
            block_id = struct.pack("<II", c, l)
            block_bytes = blake2b_long(H0 + block_id, ARGON2_BLOCK_SIZE)
            memory[l][c] = list(struct.unpack("<128Q", block_bytes))

    # 5. Główna pętla miksująca w czasie i przestrzeni
    for t in range(time_cost):
        for segment in range(4):
            # W pierwszej iteracji pierwsze dwie kolumny pomijamy (są już wypełnione)
            start_col = 2 if (t == 0 and segment == 0) else 0

            for l in range(parallelism):
                for c_index in range(start_col, sub_lane_length):
                    c = segment * sub_lane_length + c_index

                    # Pobieramy blok stojący bezpośrednio przed aktualnym
                    prev_block = memory[l][lane_length - 1] if c == 0 else memory[l][c - 1]

                    # Ustalamy pozycję losowego bloku referencyjnego (J1, J2)
                    J1, J2 = get_pseudo_rands(t, l, segment, mode, c_index, lane_length, prev_block)
                    ref_lane = J2 % parallelism

                    # Wyznaczanie dynamicznych granic bezpiecznego obszaru pamięci (index_alpha z C)
                    if t == 0:
                        if segment == 0:
                            reference_area_size = c - 1
                        else:
                            reference_area_size = segment * sub_lane_length + (c_index if ref_lane == l else 0) - 1
                    else:
                        reference_area_size = lane_length - sub_lane_length + c_index - 1 if ref_lane == l else lane_length - sub_lane_length - 1

                    if reference_area_size <= 0:
                        reference_area_size = 1

                    # Matematyczne mapowanie pseudo-losowych wartości na konkretny indeks kolumny
                    x = (J1 * J1) >> 32
                    y = (reference_area_size * x) >> 32
                    zz = reference_area_size - 1 - y

                    if t == 0:
                        ref_column = zz % reference_area_size
                    else:
                        ref_column = (segment * sub_lane_length + c_index + 1 + zz) % lane_length

                    # Pobieramy wskazany blok referencyjny z pamięci
                    ref_block = memory[ref_lane][ref_column]

                    # Miksujemy blok poprzedni z referencyjnym
                    nowy_blok = function_G(prev_block, ref_block)

                    # Wersja Argon2 v1.3: w pierwszej iteracji nadpisujemy pamięć,
                    # w kolejnych (t > 0) XORujemy nową zawartość ze starą komórką pamięci.
                    if t == 0:
                        memory[l][c] = nowy_blok
                    else:
                        stary_blok = memory[l][c]
                        memory[l][c] = [stary_blok[i] ^ nowy_blok[i] for i in range(ARGON2_WORDS_IN_BLOCK)]

    # 6. Finalizacja: Łączenie ostatnich bloków z każdej ścieżki za pomocą operacji XOR
    final_block = [0] * ARGON2_WORDS_IN_BLOCK
    for l in range(parallelism):
        last_block = memory[l][lane_length - 1]
        for i in range(ARGON2_WORDS_IN_BLOCK):
            final_block[i] ^= last_block[i]

    # Pakowanie struktury na bajty i wygenerowanie ostatecznego skrótu użytkownika
    final_bytes = struct.pack("<128Q", *final_block)
    return blake2b_long(final_bytes, hash_len)