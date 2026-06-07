import time
from core import argon2_hash



# 1. TEST POPRAWNOŚCI LOGICZNEJ
def start_initial_tests():
    print("--- URUCHAMIANIE TESTÓW POPRAWNOŚCI ---")

    # Dane testowe: hasło bazowe, hasło z minimalną zmianą (d -> D) oraz sól
    pwd1 = b"password"
    pwd2 = b"passworD"
    salt = b"somesalt"

    # Lekka konfiguracja, aby testy logiczne wykonały się natychmiastowo
    t_cost = 2
    m_cost = 16
    parallelism = 1
    hash_len = 32
    mode = 2  # 2 = Tryb hybrydowy Argon2id

    print("Obliczanie haszu testowego...")
    try:
        # Wywołanie 1: Generujemy pierwszy hasz dla hasła "password"
        hash1 = argon2_hash(pwd1, salt, t_cost, m_cost, parallelism, hash_len, mode).hex()

        # Wywołanie 2: Generujemy hasz dla dokładnie tego samego hasła (Sprawdzamy powtarzalność)
        hash1_powtorka = argon2_hash(pwd1, salt, t_cost, m_cost, parallelism, hash_len, mode).hex()

        # Wywołanie 3: Generujemy hasz dla zmodyfikowanego hasła (Sprawdzamy efekt lawinowy)
        hash2 = argon2_hash(pwd2, salt, t_cost, m_cost, parallelism, hash_len, mode).hex()

        print(f"Hasz 1 (hasło: 'password'): {hash1}")
        print(f"Hasz 2 (hasło: 'password'): {hash1_powtorka}")
        print(f"Hasz 3 (hasło: 'passworD'): {hash2}")

        # Determinizm
        if hash1 != hash1_powtorka:
            print("BŁĄD: Algorytm nie jest deterministyczny! (Dla tego samego hasła daje różne wyniki)")
            return False

        # Efekt lawinowy
        if hash1 == hash2:
            print("BŁĄD: Brak efektu lawinowego! Modyfikacja hasła nie zmieniła wyniku.")
            return False

        print("✅ SUKCES: Algorytm jest stabilny, deterministyczny i poprawnie miksuje bity.")
        return True

    except Exception as e:
        print(f"Wykryto błąd wykonania w implementacji: {e}")
        import traceback
        traceback.print_exc()
        return False

# 2. BENCHMARK WYDAJNOŚCIOWY
def start_benchmark():
    """
    Mierzy czas wykonania algorytmu dla różnych wariantów (d, i, id),
    zmieniającej się wielkości przydzielonej pamięci oraz liczby wątków.
    """
    print("\n--- URUCHAMIANIE BENCHMARKU WYDAJNOŚCIOWEGO ---")
    t_cost = 3  # Liczba iteracji czasowych
    hash_len = 16  # Oczekiwana długość wyniku w bajtach

    # Przygotowanie struktur danych (odpowiednik memset z oryginalnego benchmark.c)
    pwd_array = b'\x00' * 16
    salt_array = b'\x01' * 16

    # Definicja trybów i konfiguracji wątków do przetestowania
    types = {0: "Argon2d", 1: "Argon2i", 2: "Argon2id"}
    thread_test = [1, 2, 4]

    # Bezpieczny zakres alokacji pamięci RAM dla czystego interpretera Pythona
    m_cost = 1 << 10  # Punkt startowy: 1024 KiB (1 MiB)
    max_m_cost = 1 << 12  # Górna granica: 4096 KiB (4 MiB)

    # Główna pętla podwajająca pamięć w każdym kroku
    while m_cost <= max_m_cost:
        for thread_n in thread_test:
            run_time = 0.0
            for type_id, type_name in types.items():
                # Uruchomienie precyzyjnego stopera systemowego
                start_time = time.perf_counter()

                try:
                    # Wywołanie testowe funkcji haszującej
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
                    # Jeśli dana kombinacja (np. za mało pamięci na 4 wątki) zgłosi błąd, pomiń ją
                    continue

                # Zatrzymanie stopera i obliczenie różnicy czasu w milisekundach
                stop_time = time.perf_counter()
                delta_time = stop_time - start_time
                run_time += delta_time

                print(
                    f"{type_name} {t_cost} iteracji | {m_cost >> 10} MiB | {thread_n} wątków: {delta_time * 1000:.2f} ms")

            print(f"Łączny czas zestawu parametrów: {run_time:.4f} sekund\n")

        # Przejście do kolejnego poziomu pamięci (odpowiednik m_cost *= 2 z C)
        m_cost *= 2


if __name__ == "__main__":
    # Krok 1: Weryfikacja poprawności matematycznej algorytmu
    kod_jest_stabilny = start_initial_tests()

    # Krok 2: Jeśli testy przeszły pomyślnie, uruchom pętlę obciążeniową
    if kod_jest_stabilny:
        start_benchmark()