"""
Miletus (KongTuke) PowerShell dropper deobfuscator.

Usage:
    python3 solve_miletus.py virus.ps1

What it does:
    1. Uses ps_deobf.py (a small PowerShell-expression tokenizer/evaluator) to
       collapse the thousands of chained .Insert()/.Remove()/.Replace()/-f/-join
       string-building calls in the obfuscated script down to plain text, and
       writes the result to <input>.stage1_readable.txt for manual review.
    2. Locates the giant base64 blob passed to the custom XOR helper
       (wKHbqsr1Ft2R) inside the "815050" case block, replicates that XOR
       routine in Python (key = 4 bytes of an int + UTF8 bytes of a key
       string), base64-decodes the result, gzip-decompresses it, and writes
       the fully recovered Stage 2 PowerShell script to <input>.stage2.ps1.

This is purely static analysis -- nothing here executes the malware or makes
any network connection.
"""
import re
import sys
import base64
import gzip

from ps_deobf import tokenize, collapse_parens, render_tokens_to_text


def extract_balanced_brace_block(content: str, marker: str) -> str:
    """Return the text inside the { ... } that immediately follows `marker`,
    respecting single-quoted strings (with '' escapes) so braces inside
    string literals don't confuse the matcher."""
    start = content.find(marker)
    if start == -1:
        raise ValueError(f"marker {marker!r} not found")
    i = start + len(marker)
    depth = 1
    j = i
    n = len(content)
    in_str = False
    while j < n and depth > 0:
        c = content[j]
        if c == "'":
            if in_str and j + 1 < n and content[j + 1] == "'":
                j += 2
                continue
            in_str = not in_str
            j += 1
            continue
        if not in_str:
            if c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0:
                    break
        j += 1
    return content[i:j]


def deobfuscate_readable(content: str) -> str:
    """Best-effort textual deobfuscation of the whole script (collapses pure
    string-literal expressions into plain strings; leaves anything that
    depends on runtime variables mostly intact)."""
    tokens = tokenize(content)
    tokens = collapse_parens(tokens)
    return render_tokens_to_text(tokens)


def xor_decode(blob_b64: str, key_int: int, key_str: str) -> str:
    """Re-implementation of the malware's custom wKHbqsr1Ft2R() helper in
    decode ('d') mode:
        key   = BitConverter.GetBytes(key_int) + UTF8.GetBytes(key_str)
        input = Base64Decode(blob_b64)
        out[i] = input[i] XOR key[i % len(key)]
        return UTF8.GetString(out)
    """
    key = key_int.to_bytes(4, byteorder='little') + key_str.encode('utf-8')
    data = base64.b64decode(blob_b64)
    xored = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
    return xored.decode('utf-8')


def recover_stage2(content: str) -> str:
    """Find the wKHbqsr1Ft2R(...) call inside the '815050' case block. The
    blob, mode, and key arguments are all built via chained
    .Insert()/.Remove()/.Replace() calls, so we first run them through the
    same collapse_parens() pass used for the readable dump, then pull the
    resolved string literals out of that readable text."""
    block = extract_balanced_brace_block(content, "815050{")

    tokens = tokenize(block)
    tokens = collapse_parens(tokens)
    readable = render_tokens_to_text(tokens)

    marker = "'wKHbqsr1Ft2R'"
    start = readable.find(marker)
    if start == -1:
        raise ValueError("could not find wKHbqsr1Ft2R call in readable block")
    # Everything up to the GZipStream constructor call belongs to this call's args.
    end = readable.find(",[IO.Compression", start)
    if end == -1:
        end = len(readable)
    segment = readable[start + len(marker):end]

    quoted = re.findall(r"'((?:[^']|'')*)'", segment)
    if len(quoted) < 2:
        raise ValueError(f"expected at least blob+key strings, got {quoted!r}")

    blob = quoted[0]
    # mode is the short 'd'/'e' string; key is the last (longest, non-mode) literal
    key_str = quoted[-1]
    key_int = 1  # [int]$true from the AMSI amsiInitFailed field, set True earlier

    b64_of_gzip = xor_decode(blob, key_int, key_str)
    gzip_bytes = base64.b64decode(b64_of_gzip)
    return gzip.decompress(gzip_bytes).decode('utf-8')


def main():
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} virus.ps1", file=sys.stderr)
        sys.exit(1)

    path = sys.argv[1]
    with open(path, 'r') as f:
        content = f.read()

    readable = deobfuscate_readable(content)
    out1 = path + '.stage1_readable.txt'
    with open(out1, 'w') as f:
        f.write(readable)
    print(f"[+] wrote readable Stage 1 reconstruction -> {out1}")

    try:
        stage2 = recover_stage2(content)
        out2 = path + '.stage2.ps1'
        with open(out2, 'w') as f:
            f.write(stage2)
        print(f"[+] wrote fully decoded Stage 2 script  -> {out2}")
    except Exception as e:
        print(f"[!] stage2 recovery failed: {e}", file=sys.stderr)


if __name__ == '__main__':
    main()
