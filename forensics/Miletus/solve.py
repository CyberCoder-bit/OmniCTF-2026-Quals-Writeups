"""
Usage:
    python3 solve.py virus.ps1
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


def pretty_print_ps(code: str, indent_str: str = "    ") -> str:
    """Very small PowerShell pretty-printer: breaks lines on ';' (only at
    paren-depth 0, so 'for(a;b;c)' headers stay on one line) and on
    '{'/'}', indenting nested blocks. Respects single- and double-quoted
    string literals (including '' escapes) so semicolons/braces inside
    strings don't get split on."""
    out_lines = []
    cur = []
    depth = 0
    paren_depth = 0
    i = 0
    n = len(code)
    in_single = False
    in_double = False

    def flush():
        line = ''.join(cur).strip()
        if line:
            out_lines.append(indent_str * depth + line)
        cur.clear()

    while i < n:
        c = code[i]
        if in_single:
            cur.append(c)
            if c == "'":
                if i + 1 < n and code[i+1] == "'":
                    cur.append(code[i+1])
                    i += 2
                    continue
                in_single = False
            i += 1
            continue
        if in_double:
            cur.append(c)
            if c == '"':
                in_double = False
            i += 1
            continue
        if c == "'":
            in_single = True
            cur.append(c)
            i += 1
            continue
        if c == '"':
            in_double = True
            cur.append(c)
            i += 1
            continue
        if c == '(':
            paren_depth += 1
            cur.append(c)
            i += 1
            continue
        if c == ')':
            paren_depth = max(0, paren_depth - 1)
            cur.append(c)
            i += 1
            continue
        if c == '{':
            cur.append(c)
            flush()
            depth += 1
            i += 1
            continue
        if c == '}':
            flush()
            depth = max(0, depth - 1)
            cur.append(c)
            # peek ahead: if immediately followed by ';', keep it on this line
            if i + 1 < n and code[i+1] == ';':
                cur.append(';')
                i += 1
            flush()
            i += 1
            continue
        if c == ';' and paren_depth == 0:
            cur.append(c)
            flush()
            i += 1
            continue
        cur.append(c)
        i += 1
    flush()
    return '\n'.join(out_lines)



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

        stage2_fmt = pretty_print_ps(stage2)
        out2_fmt = path + '.stage2.formatted.ps1'
        with open(out2_fmt, 'w') as f:
            f.write(stage2_fmt)
        print(f"[+] wrote formatted Stage 2 script      -> {out2_fmt}")
    except Exception as e:
        print(f"[!] stage2 recovery failed: {e}", file=sys.stderr)


if __name__ == '__main__':
    main()
