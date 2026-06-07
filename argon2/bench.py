import time
# Importujemy funkcję z Twojego core.py
from core import argon2_hash


# =====================================================================
# 1. TEST DETERMINIZMU I BEZPIECZEŃSTWA (Lokalna weryfikacja poprawności)
# =====================================================================
def uruchom_testy_poprawnosci():
    print("--- URUCHAMIANIE TESTÓW POPRAWNOŚCI ---")

    pwd1 = b"password"
    pwd2 = b"passworD"  # Minimalna zmiana (wielka litera na końcu)
    salt = b"somesalt"

    t_cost = 2
    m_cost = 16
    parallelism = 1
    hash_len = 32
    mode = 2  # Argon2id

    print("Obliczanie haszu testowego...")
    try:
        # Wywołanie 1: Generujemy pierwszy hasz
        hash1 = argon2_hash(pwd1, salt, t_cost, m_cost, parallelism, hash_len, mode).hex()

        # Wywołanie 2: Generujemy hasz dla dokładnie tego samego hasła (Sprawdzamy determinizm)
        hash1_powtorka = argon2_hash(pwd1, salt, t_cost, m_cost, parallelism, hash_len, mode).hex()

        # Wywołanie 3: Generujemy hasz dla zmienionego hasła (Sprawdzamy efekt lawinowy)
        hash2 = argon2_hash(pwd2, salt, t_cost, m_cost, parallelism, hash_len, mode).hex()

        print(f"Hasz 1 (hasło: 'password'): {hash1}")
        print(f"Hasz 2 (hasło: 'password'): {hash1_powtorka}")
        print(f"Hasz 3 (hasło: 'passworD'): {hash2}")

        # Weryfikacja logiczna działania algorytmu
        if hash1 != hash1_powtorka:
            print("❌ BŁĄD: Algorytm nie jest deterministyczny! (Dla tego samego hasła daje różne wyniki)")
            return False

        if hash1 == hash2:
            print("❌ BŁĄD: Brak efektu lawinowego! Modyfikacja hasła nie zmieniła wyniku.")
            return False

        print("✅ SUKCES: Algorytm jest stabilny, deterministyczny i poprawnie miksuje bity (efekt lawinowy działa)!")
        return True

    except Exception as e:
        print(f"💥 KRAKRA KODU: Wykryto błąd wykonania w implementacji: {e}")
        import traceback
        traceback.print_exc()
        return False


# =====================================================================
# 2. BENCHMARK (Dokładnie tak jak w kodzie C)
# =====================================================================
def uruchom_benchmark():
    print("\n--- URUCHAMIANIE BENCHMARKU WYDAJNOŚCIOWEGO ---")
    t_cost = 3
    hash_len = 16

    pwd_array = b'\x00' * 16
    salt_array = b'\x01' * 16

    types = {0: "Argon2d", 1: "Argon2i", 2: "Argon2id"}
    thread_test = [1, 2, 4]

    # Bezpieczny zakres dla czystego Pythona
    m_cost = 1 << 10  # 1024 KiB (1 MiB)
    max_m_cost = 1 << 12  # 4096 KiB (4 MiB)

    while m_cost <= max_m_cost:
        for thread_n in thread_test:
            run_time = 0.0
            for type_id, type_name in types.items():
                start_time = time.perf_counter()

                try:
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
                    continue

                stop_time = time.perf_counter()
                delta_time = stop_time - start_time
                run_time += delta_time

                print(
                    f"{type_name} {t_cost} iteracji | {m_cost >> 10} MiB | {thread_n} wątków: {delta_time * 1000:.2f} ms")

            print(f"Łączny czas zestawu parametrów: {run_time:.4f} sekund\n")
        m_cost *= 2


if __name__ == "__main__":
    # Sprawdzamy stabilność matematyczną kodu
    kod_jest_stabilny = uruchom_testy_poprawnosci()

    # Jeśli testy przeszły, odpalany jest benchmark wydajnościowy (identyczny z tym z C)
    if kod_jest_stabilny:
        uruchom_benchmark()