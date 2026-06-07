import sys
import argparse
from core import argon2_hash


def main():
    # 1. Inicjalizacja parsera argumentów linii komend
    parser = argparse.ArgumentParser(description="Argon2 w Pythonie")

    # Sól to jedyny argument pozycyjny (wymagany)
    parser.add_argument("salt", help="Sól do hashowania (min. 8 znaków)")

    # 2. Tworzenie grupy wzajemnie wykluczających się opcji dla wyboru trybu algorytmu
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-i", action="store_const", dest="mode", const=1, help="Użyj Argon2i (domyślny)")
    group.add_argument("-d", action="store_const", dest="mode", const=0, help="Użyj Argon2d")
    group.add_argument("-id", action="store_const", dest="mode", const=2, help="Użyj Argon2id")

    # Jeśli użytkownik nie wybierze flagi, domyślnie odpali się Argon2i (mode=1)
    parser.set_defaults(mode=1)

    # 3. Definiowanie opcjonalnych parametrów konfiguracyjnych (flagi -t, -m, -p, -l)
    parser.add_argument("-t", type=int, default=3, help="Liczba iteracji / koszt czasowy (domyślnie 3)")
    parser.add_argument("-m", type=int, default=12, help="Wykładnik pamięci 2^N KiB (domyślnie 12, czyli 4096 KiB)")
    parser.add_argument("-p", type=int, default=1, help="Równoległość / stopień użycia wątków (domyślnie 1)")
    parser.add_argument("-l", type=int, default=32, dest="l", help="Docelowa długość hasha w bajtach (domyślnie 32)")

    # Przetworzenie wpisanych przez użytkownika argumentów do obiektu 'args'
    args = parser.parse_args()

    # 4. Blokada bezpieczeństwa: sprawdzenie czy hasło płynie przez potok (pipe '|')
    # sys.stdin.isatty() zwraca True, jeśli program został odpalony "goły" i czeka na wpisywanie z klawiatury
    if sys.stdin.isatty():
        print("BŁĄD: Podaj hasło przez strumień wejścia (pipe)!")
        print("Przykład: echo -n 'password' | python cli.py somesalt -t 2 -m 16 -p 4 -l 24")
        sys.exit(1)

    # 5. Pobranie danych wejściowych z potoku oraz konwersja typów
    pwd = sys.stdin.read().encode('utf-8')  # Odczyt hasła ze strumienia i zamiana na bajty
    salt = args.salt.encode('utf-8')  # Zamiana tekstowej soli na bajty

    # Przeliczenie kosztu pamięciowego za pomocą przesunięcia bitowego (potęgowanie dwójki)
    m_cost = 1 << args.m  # Np. 1 << 12 daje binarnie 4096 KiB (4 MiB)

    # 6. Wywołanie głównej funkcji kryptograficznej z pliku core.py
    hash_bytes = argon2_hash(
        password=pwd,
        salt=salt,
        time_cost=args.t,
        memory_cost=m_cost,
        parallelism=args.p,
        hash_len=args.l,
        mode=args.mode
    )

    # 7. Słownik mapujący identyfikatory liczbowe na czytelne nazwy wariantów
    mode_name = {0: "Argon2d", 1: "Argon2i", 2: "Argon2id"}[args.mode]

    # 8. Wyświetlenie raportu końcowego w formacie zgodnym z oficjalną aplikacją w C
    print(f"Type:           {mode_name}")
    print(f"Iterations:     {args.t}")
    print(f"Memory:         {m_cost} KiB")
    print(f"Parallelism:    {args.p}")
    print(f"Hash:           {hash_bytes.hex()}")


if __name__ == "__main__":
    main()