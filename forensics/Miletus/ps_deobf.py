import sys, re

sys.setrecursionlimit(100000)

class TypeRef:
    def __init__(self, name): self.name = name
    def __repr__(self): return f"[{self.name}]"

class VarRef:
    def __init__(self, name): self.name = name
    def __repr__(self): return self.name

class Opaque:
    def __init__(self, text): self.text = text
    def __repr__(self): return self.text
    def __str__(self): return self.text

def render(v):
    if v is None:
        return ""
    if isinstance(v, list):
        return ",".join(render(x) for x in v)
    if isinstance(v, str):
        return "'" + v.replace("'", "''") + "'"
    return str(v)

def tokenize(text):
    tokens = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c.isspace():
            i += 1; continue
        if c == "'":
            j = i+1
            buf = []
            while j < n:
                if text[j] == "'":
                    if j+1 < n and text[j+1] == "'":
                        buf.append("'"); j += 2; continue
                    else:
                        break
                buf.append(text[j]); j += 1
            tokens.append(('STR', ''.join(buf)))
            i = j+1
            continue
        if c == '"':
            j = i+1
            buf = []
            while j < n and text[j] != '"':
                buf.append(text[j]); j += 1
            tokens.append(('STR', ''.join(buf)))
            i = j+1
            continue
        if c == '[':
            depth = 1
            j = i+1
            while j < n and depth > 0:
                if text[j] == '[': depth += 1
                elif text[j] == ']': depth -= 1
                j += 1
            tokens.append(('TYPE', text[i:j]))
            i = j
            continue
        if c == '$':
            if i+1 < n and text[i+1] == '(':
                tokens.append(('OP', '$'))
                i += 1
                continue
            j = i+1
            while j < n and (text[j].isalnum() or text[j] == '_'):
                j += 1
            tokens.append(('VAR', text[i:j]))
            i = j
            continue
        if c == '-':
            j = i+1
            while j < n and text[j].isalpha():
                j += 1
            word = text[i:j]
            if len(word) > 1:
                tokens.append(('OP', word))
                i = j
                continue
            else:
                tokens.append(('OP', '-'))
                i += 1
                continue
        if c == ':' and i+1 < n and text[i+1] == ':':
            tokens.append(('OP', '::'))
            i += 2
            continue
        if c in '(),.+@;={}':
            tokens.append(('OP', c))
            i += 1
            continue
        if c.isdigit():
            j = i
            while j < n and text[j].isdigit():
                j += 1
            tokens.append(('NUM', text[i:j]))
            i = j
            continue
        if c.isalpha() or c == '_':
            j = i
            while j < n and (text[j].isalnum() or text[j] == '_'):
                j += 1
            tokens.append(('IDENT', text[i:j]))
            i = j
            continue
        tokens.append(('OP', c))
        i += 1
    return tokens


def evaluate_flat(tokens):
    pos = [0]
    def peek():
        return tokens[pos[0]] if pos[0] < len(tokens) else None
    def nxt():
        t = tokens[pos[0]]; pos[0] += 1; return t

    def parse_expr():
        return parse_join()

    def parse_join():
        if peek() and peek()[0]=='OP' and peek()[1]=='-join':
            nxt()
            val = parse_format()
            items = val if isinstance(val, list) else [val]
            try:
                return ''.join(str(x) for x in items)
            except Exception:
                return Opaque('-join ' + render(val))
        return parse_format()

    def parse_format():
        left = parse_concat()
        if peek() and peek()[0]=='OP' and peek()[1]=='-f':
            nxt()
            args = [parse_concat()]
            while peek() and peek()[0]=='OP' and peek()[1]==',':
                nxt()
                args.append(parse_concat())
            try:
                return str(left).format(*[str(a) for a in args])
            except Exception:
                return Opaque(f"{render(left)} -f {','.join(render(a) for a in args)}")
        return left

    def parse_concat():
        left = parse_as()
        while peek() and peek()[0]=='OP' and peek()[1]=='+':
            nxt()
            right = parse_as()
            try:
                left = str(left) + str(right)
            except Exception:
                left = Opaque(render(left)+"+"+render(right))
        return left

    def parse_as():
        left = parse_postfix()
        if peek() and peek()[0]=='OP' and peek()[1]=='-as':
            nxt()
            tname = None
            if peek() and peek()[0]=='TYPE':
                tname = nxt()[1]
            if isinstance(left, str):
                return TypeRef(left)
            return left
        return left

    def call_method(obj, name, args):
        arglist = args if isinstance(args, list) else ([args] if args is not None else [])
        if isinstance(obj, str):
            try:
                if name == 'Insert':
                    idx, s = int(arglist[0]), str(arglist[1])
                    return obj[:idx] + s + obj[idx:]
                if name == 'Remove':
                    if len(arglist) == 1:
                        return obj[:int(arglist[0])]
                    idx, cnt = int(arglist[0]), int(arglist[1])
                    return obj[:idx] + obj[idx+cnt:]
                if name == 'Replace':
                    old, new = str(arglist[0]), str(arglist[1])
                    return obj.replace(old, new)
                if name == 'ToString':
                    return obj
                if name == 'ToLower':
                    return obj.lower()
                if name == 'ToUpper':
                    return obj.upper()
                if name == 'Substring':
                    if len(arglist) == 1:
                        return obj[int(arglist[0]):]
                    return obj[int(arglist[0]):int(arglist[0])+int(arglist[1])]
                if name == 'Trim':
                    return obj.strip()
                if name == 'Split':
                    return obj.split(str(arglist[0]))
            except Exception:
                pass
        return Opaque(f"{render(obj)}.{name}({render(args) if args is not None else ''})")

    def call_static(obj, name, args):
        if isinstance(obj, TypeRef):
            tn = obj.name.lower()
            if tn in ('string','system.string') and name == 'Concat':
                arglist = args if isinstance(args, list) else [args]
                try:
                    return ''.join(str(x) for x in arglist)
                except Exception:
                    pass
        return Opaque(f"{render(obj)}::{name}({render(args) if args is not None else ''})")

    def parse_primary():
        tok = peek()
        if tok is None:
            return None
        if tok[0] == 'STR':
            nxt(); return tok[1]
        if tok[0] == 'NUM':
            nxt(); return int(tok[1])
        if tok[0] == 'VAR':
            nxt()
            if tok[1] == '$null': return None
            if tok[1] == '$true': return True
            if tok[1] == '$false': return False
            return VarRef(tok[1])
        if tok[0] == 'VAL':
            nxt(); return tok[1]
        if tok[0] == 'TYPE':
            nxt()
            name = tok[1].strip('[]')
            return TypeRef(name)
        if tok[0] == 'OP' and tok[1] == '$':
            nxt()
            return parse_primary()
        if tok[0] == 'OP' and tok[1] == '@':
            nxt()
            val = parse_primary()
            if not isinstance(val, list):
                val = [] if val is None else [val]
            return val
        if tok[0] == 'IDENT':
            nxt()
            args = None
            if peek() and peek()[0] == 'VAL':
                args = nxt()[1]
            if args is not None:
                return Opaque(f"{tok[1]}({render(args)})")
            return Opaque(tok[1])
        nxt()
        return Opaque(str(tok))

    def parse_postfix():
        left = parse_primary()
        while True:
            tok = peek()
            if tok and tok[0]=='OP' and tok[1]=='.':
                nxt()
                idname = nxt()
                ident = idname[1] if idname[0]=='IDENT' else str(idname)
                args = None
                if peek() and peek()[0]=='VAL':
                    args = nxt()[1]
                left = call_method(left, ident, args)
            elif tok and tok[0]=='OP' and tok[1]=='::':
                nxt()
                idname = nxt()
                ident = idname[1] if idname[0]=='IDENT' else str(idname)
                args = None
                if peek() and peek()[0]=='VAL':
                    args = nxt()[1]
                left = call_static(left, ident, args)
            else:
                break
        return left

    results = []
    if not tokens:
        return None
    while True:
        val = parse_expr()
        results.append(val)
        if peek() and peek()[0]=='OP' and peek()[1]==',':
            nxt()
            continue
        break
    if pos[0] != len(tokens):
        # leftover unparsed tokens -> opaque fallback
        return Opaque(' '.join(render(t[1]) if t[0]!='OP' else t[1] for t in tokens))
    if len(results) == 1:
        return results[0]
    return results


def collapse_parens(tokens):
    toks = tokens[:]
    while True:
        close_idx = None
        for idx, (t, v) in enumerate(toks):
            if t == 'OP' and v == ')':
                close_idx = idx
                break
        if close_idx is None:
            break
        depth = 0
        open_idx = None
        for idx in range(close_idx-1, -1, -1):
            t, v = toks[idx]
            if t == 'OP' and v == ')':
                depth += 1
            elif t == 'OP' and v == '(':
                if depth == 0:
                    open_idx = idx
                    break
                else:
                    depth -= 1
        if open_idx is None:
            # stray ')' - drop it to make progress
            toks = toks[:close_idx] + toks[close_idx+1:]
            continue
        inner = toks[open_idx+1:close_idx]
        try:
            val = evaluate_flat(inner)
        except Exception as e:
            val = Opaque('(' + ' '.join(str(t[1]) for t in inner) + ')')
        toks = toks[:open_idx] + [('VAL', val)] + toks[close_idx+1:]
    return toks


def render_tokens_to_text(tokens):
    parts = []
    for t, v in tokens:
        if t == 'STR':
            parts.append("'" + str(v).replace("'", "''") + "'")
        elif t == 'VAL':
            if isinstance(v, list):
                parts.append('@(' + ','.join(render(x) for x in v) + ')')
            elif isinstance(v, str):
                parts.append("'" + v.replace("'", "''") + "'")
            else:
                parts.append(render(v))
        elif t == 'VAR':
            parts.append(v)
        elif t == 'TYPE':
            parts.append(v)
        elif t == 'NUM':
            parts.append(v)
        else:
            parts.append(v)
    return ' '.join(parts)


def deobfuscate_expr(text):
    tokens = tokenize(text)
    tokens = collapse_parens(tokens)
    val = evaluate_flat(tokens)
    return val

if __name__ == '__main__':
    with open(sys.argv[1]) as f:
        content = f.read()
    tokens = tokenize(content)
    print(f"Tokenized: {len(tokens)} tokens", file=sys.stderr)
    tokens = collapse_parens(tokens)
    print(f"Collapsed: {len(tokens)} tokens remain", file=sys.stderr)
    text = render_tokens_to_text(tokens)
    with open(sys.argv[2], 'w') as f:
        f.write(text)
    print("done", file=sys.stderr)

