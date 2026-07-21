#!/usr/bin/env python3
"""
Optimized 2DES meet-in-the-middle solver with MD5 validation.

This solver uses the known SHA-256-style flag structure:

    ctf{64 lowercase hexadecimal characters}

The two DES keys are substrings of the flag:

    key1 = flag[:8]
    key2 = flag[-8:]

Therefore:

    key1 = b"ctf{" + first 4 hex characters
    key2 = final 7 hex characters + b"}"

DES ignores the low parity bit of each key byte, so many ASCII characters
are equivalent as DES keys. We search only one representative from each
relevant parity-equivalence class, then expand the matching classes and use
the challenge-supplied MD5 to select the exact original flag spelling.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from itertools import product

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad


VALIDATION_MD5 = "b029aefa19e1889303614610be7d3295"

KNOWN_PREFIX = b"ctf{"
KNOWN_SUFFIX = b"}"

KNOWN_PLAINTEXT = b"supersaferight?"

KNOWN_CIPHERTEXT = bytes.fromhex(
    "57bd461497e572b0c5ec06c12d1ed8ce"
)

MIDDLE_CIPHERTEXT = bytes.fromhex(
    "2ac5e1b3799e3a0e"
    "9c6d6be856a33509"
    "b04a12f01b73ad0c"
    "f0d6af1225c933c5"
    "28c65a6b30b5fe76"
    "fb62df849e606c7d"
    "852a8f9270538a9f"
)

# One DES-effective representative for every lowercase hexadecimal character.
#
# Equivalence classes:
#   0/1, 2/3, 4/5, 6/7, 8/9, a, b/c, d/e, f
CANONICAL_HEX = b"02468abdf"

# Every original lowercase hexadecimal character represented by each canonical
# DES key byte.
PARITY_VARIANTS = {
    ord("0"): "01",
    ord("2"): "23",
    ord("4"): "45",
    ord("6"): "67",
    ord("8"): "89",
    ord("a"): "a",
    ord("b"): "bc",
    ord("d"): "de",
    ord("f"): "f",
}


def validate_inputs() -> None:
    """Validate all fixed challenge inputs before starting the search."""
    if len(KNOWN_PREFIX) != 4:
        raise ValueError("KNOWN_PREFIX must be exactly four bytes")

    if len(KNOWN_SUFFIX) != 1:
        raise ValueError("KNOWN_SUFFIX must be exactly one byte")

    if len(KNOWN_CIPHERTEXT) == 0 or len(KNOWN_CIPHERTEXT) % DES.block_size:
        raise ValueError(
            "KNOWN_CIPHERTEXT length must be a non-zero multiple of 8 bytes"
        )

    if len(MIDDLE_CIPHERTEXT) == 0 or len(MIDDLE_CIPHERTEXT) % DES.block_size:
        raise ValueError(
            "MIDDLE_CIPHERTEXT length must be a non-zero multiple of 8 bytes"
        )

    if len(VALIDATION_MD5) != 32:
        raise ValueError("VALIDATION_MD5 must contain exactly 32 hex characters")

    try:
        bytes.fromhex(VALIDATION_MD5)
    except ValueError as exc:
        raise ValueError("VALIDATION_MD5 is not valid hexadecimal") from exc


def validate_flag_hash(flag: bytes) -> bool:
    """Return True when the full flag bytes match the supplied MD5."""
    return hashlib.md5(flag).hexdigest() == VALIDATION_MD5.lower()


def des_encrypt_block(block: bytes, key: bytes) -> bytes:
    return DES.new(key, DES.MODE_ECB).encrypt(block)


def des_decrypt_block(block: bytes, key: bytes) -> bytes:
    return DES.new(key, DES.MODE_ECB).decrypt(block)


def double_des_decrypt(ciphertext: bytes, key1: bytes, key2: bytes) -> bytes:
    """Decrypt E_key2(E_key1(plaintext))."""
    after_key2 = DES.new(key2, DES.MODE_ECB).decrypt(ciphertext)
    return DES.new(key1, DES.MODE_ECB).decrypt(after_key2)


def expand_parity_variants(canonical: bytes):
    """
    Yield every lowercase-hex spelling represented by a canonical DES key.

    Example:
        b"0246" expands across:
        0/1, 2/3, 4/5, 6/7
    """
    pools = [PARITY_VARIANTS[byte] for byte in canonical]

    for combination in product(*pools):
        yield "".join(combination).encode("ascii")


def recover_effective_keys():
    """
    Recover canonical key1/key2 pairs using a meet-in-the-middle lookup.

    Returns tuples:
        (canonical_key1_suffix, decrypted_middle, canonical_key2_prefix)
    """
    padded_known = pad(KNOWN_PLAINTEXT, DES.block_size)

    plaintext_block = padded_known[:DES.block_size]
    ciphertext_block = KNOWN_CIPHERTEXT[:DES.block_size]

    forward: dict[bytes, list[tuple[bytes, bytes]]] = defaultdict(list)

    print("[*] Building canonical key1 table...")

    # key1 = b"ctf{" + first four SHA-256 hexadecimal characters
    for suffix_tuple in product(CANONICAL_HEX, repeat=4):
        suffix = bytes(suffix_tuple)
        key1 = KNOWN_PREFIX + suffix

        intermediate = des_encrypt_block(plaintext_block, key1)
        forward[intermediate].append((key1, suffix))

    print(f"[*] Stored {len(forward):,} unique intermediate values")
    print(f"[*] Searching {len(CANONICAL_HEX) ** 7:,} canonical key2 candidates...")

    matches = []

    # key2 = final seven SHA-256 hexadecimal characters + b"}"
    for ending_tuple in product(CANONICAL_HEX, repeat=7):
        ending = bytes(ending_tuple)
        key2 = ending + KNOWN_SUFFIX

        intermediate = des_decrypt_block(ciphertext_block, key2)
        key1_matches = forward.get(intermediate)

        if not key1_matches:
            continue

        for key1, beginning in key1_matches:
            # Verify the candidate against the complete known pair, not only
            # the first block used for the MITM lookup.
            first_layer = DES.new(key1, DES.MODE_ECB).encrypt(padded_known)
            complete_test = DES.new(key2, DES.MODE_ECB).encrypt(first_layer)

            if complete_test != KNOWN_CIPHERTEXT:
                continue

            try:
                middle_padded = double_des_decrypt(
                    MIDDLE_CIPHERTEXT,
                    key1,
                    key2,
                )
                middle = unpad(middle_padded, DES.block_size)
            except ValueError:
                continue

            # A 64-character SHA-256 value is split as:
            #   first 4 chars in key1
            #   middle 53 chars in encrypted payload
            #   final 7 chars in key2
            if len(middle) != 53:
                continue

            if any(byte not in b"0123456789abcdef" for byte in middle):
                continue

            matches.append((beginning, middle, ending))

            print("\n[+] Canonical effective keys recovered")
            print(f"    key1:   {key1!r}")
            print(f"    key2:   {key2!r}")
            print(f"    middle: {middle.decode('ascii')}")

    return matches


def recover_exact_flag(matches):
    """
    Expand parity-equivalent spellings and use the supplied MD5 to recover the
    exact original flag.
    """
    checked = 0
    structural_candidates = 0

    for beginning, middle, ending in matches:
        for beginning_variant in expand_parity_variants(beginning):
            for ending_variant in expand_parity_variants(ending):
                flag = (
                    KNOWN_PREFIX
                    + beginning_variant
                    + middle
                    + ending_variant
                    + KNOWN_SUFFIX
                )

                structural_candidates += 1
                checked += 1

                if validate_flag_hash(flag):
                    print("\n[+] MD5 validation succeeded")
                    print(f"    FLAG: {flag.decode('ascii')}")
                    print(f"    MD5:  {hashlib.md5(flag).hexdigest()}")
                    return flag

    print(
        "\n[-] No parity-expanded candidate matched the supplied MD5 "
        f"after checking {checked:,} candidate(s)."
    )

    if structural_candidates:
        print(
            "[!] Effective DES keys were recovered, so verify the supplied "
            "validation hash and ciphertext bytes."
        )

    return None


def main() -> int:
    try:
        validate_inputs()
    except ValueError as exc:
        print(f"[-] Input error: {exc}")
        return 2

    matches = recover_effective_keys()

    if not matches:
        print("\n[-] No matching effective DES keys found.")
        print("    Verify both ciphertexts and the known plaintext.")
        return 1

    print(f"\n[*] Found {len(matches)} effective key match(es).")
    flag = recover_exact_flag(matches)

    if flag is None:
        return 1

    print("\n[+] Final verified result")
    print(f"    {flag.decode('ascii')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
