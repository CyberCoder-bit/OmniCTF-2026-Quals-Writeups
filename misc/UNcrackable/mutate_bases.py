#!/usr/bin/env python3

import sys

LOW_A = ord("a")
LOW_Z = ord("z")
UP_A = ord("A")
UP_Z = ord("Z")


def is_letter(c: int) -> bool:
    return LOW_A <= c <= LOW_Z or UP_A <= c <= UP_Z


def uppercase(c: int) -> int:
    return c - 32 if LOW_A <= c <= LOW_Z else c


def toggle(c: int) -> int:
    if LOW_A <= c <= LOW_Z:
        return c - 32
    if UP_A <= c <= UP_Z:
        return c + 32
    return c


def capitalized_forms(word: bytes):
    # Interpretation 1: uppercase first character only.
    first_only = bytearray(word)

    if first_only:
        first_only[0] = uppercase(first_only[0])

    yield bytes(first_only)

    # Interpretation 2: Python bytes.capitalize().
    python_cap = bytearray(word.lower())

    if python_cap:
        python_cap[0] = uppercase(python_cap[0])

    python_cap = bytes(python_cap)

    if python_cap != bytes(first_only):
        yield python_cap


def variants(word: bytes):
    seen = set()

    for capitalized in capitalized_forms(word):
        start = max(0, len(capitalized) - 3)

        positions = [
            p
            for p in range(start, len(capitalized))
            if is_letter(capitalized[p])
        ]

        if not positions:
            seen.add(capitalized)
            continue

        for p in positions:
            candidate = bytearray(capitalized)
            candidate[p] = toggle(candidate[p])
            seen.add(bytes(candidate))

    return seen


def main():
    if len(sys.argv) != 2:
        raise SystemExit(f"Usage: {sys.argv[0]} rockyou.txt")

    output = sys.stdout.buffer
    batch = []

    with open(sys.argv[1], "rb") as wordlist:
        for raw in wordlist:
            word = raw.rstrip(b"\r\n")

            if not word:
                continue

            for candidate in variants(word):
                batch.append(candidate + b"\n")

            if len(batch) >= 100_000:
                output.writelines(batch)
                batch.clear()

    if batch:
        output.writelines(batch)


if __name__ == "__main__":
    main()
