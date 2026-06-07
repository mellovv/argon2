import sys
import argparse
from core import argon2_hash

def main():
    parser = argparse.ArgumentParser(description="Argon2 w Pythonie - Projekt BDAN")
    parser.add_argument("salt", help="Sól do hashowania (min. 8 znaków)")
    
    # Wybór trybu (domyślnie Argon2i jak w C)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-i", action="store_const", dest="mode", const=1, help="Użyj Argon2i (domyślny)")
    group.add_argument("-d", action="store_const", dest="mode", const=0, help="Użyj Argon2d")
    group.add_argument("-id", action="store_const", dest="mode", const=2, help="Użyj Argon2id")
    parser.set_defaults(mode=1)
    
    parser.add_argument("-t", type=int, default=3, help="Liczba iteracji (domyślnie 3)")
    parser.add_argument("-m", type=int, default=12, help="Pamięć w 2^N KiB (domyślnie 12)")
    parser.add_argument("-p", type=int, default=1, help="Równoległość/Wątki (domyślnie 1)")
    parser.add_argument("-l", type=int, default=32, dest="l", help="Długość hasha (domyślnie 32)")

    args = parser.parse_args()

    # Zabezpieczenie przed odpaleniem z palca bez pipe'a
    if sys.stdin.isatty():
        print("❌ BŁĄD: Podaj hasło przez strumień wejścia (pipe)!")
        print("Przykład: echo -n 'password' | python cli.py somesalt -t 2 -m 16 -p 4 -l 24")
        sys.exit(1)

    # Odczyt hasła i przeliczenie pamięci
    pwd = sys.stdin.read().encode('utf-8')
    salt = args.salt.encode('utf-8')
    m_cost = 1 << args.m  # np. 1 << 16 daje 65536 KiB

    # Wywołanie potwora z core.py
    hash_bytes = argon2_hash(
        password=pwd, 
        salt=salt, 
        time_cost=args.t, 
        memory_cost=m_cost, 
        parallelism=args.p, 
        hash_len=args.l, 
        mode=args.mode
    )

    # Wypisanie wyniku dokładnie w takim formacie jak program w C
    mode_name = {0: "Argon2d", 1: "Argon2i", 2: "Argon2id"}[args.mode]
    print(f"Type:           {mode_name}")
    print(f"Iterations:     {args.t}")
    print(f"Memory:         {m_cost} KiB")
    print(f"Parallelism:    {args.p}")
    print(f"Hash:           {hash_bytes.hex()}")

if __name__ == "__main__":
    main()
