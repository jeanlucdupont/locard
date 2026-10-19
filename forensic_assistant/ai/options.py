"""Small, typed performance-option surface; never a shell command."""
import re
import shlex

# Values are deliberately path-free. No executable, network, model-loading,
# logging, template, or credential options can enter through this surface.
NUMBERS = {'-ngl': ('gpu_layers', 0, 999), '--gpu-layers': ('gpu_layers', 0, 999),
           '-c': ('context', 512, 131072), '--ctx-size': ('context', 512, 131072),
           '-t': ('--threads', 1, 1024), '--threads': ('--threads', 1, 1024),
           '--threads-batch': ('--threads-batch', 1, 1024),
           '-b': ('--batch-size', 1, 131072), '--batch-size': ('--batch-size', 1, 131072),
           '-ub': ('--ubatch-size', 1, 131072), '--ubatch-size': ('--ubatch-size', 1, 131072)}


def parse(text):
    if type(text) is not str or len(text) > 4096 or re.search(r'[\x00-\x1f;&|<>`$%\\]', text):
        raise ValueError('Invalid extra options; shell syntax and paths are not supported')
    # Quoted scalar tokens use Windows double-quote grouping. Backslash escapes
    # cannot be needed for these numeric/enum options and are rejected above.
    lexer = shlex.shlex(text, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = ''
    lexer.quotes = '"'
    lexer.escape = ''
    try:
        tokens = list(lexer)
    except ValueError:
        raise ValueError('Unclosed quote in extra options') from None
    expanded = []
    for token in tokens:
        expanded.extend(token.split('=', 1) if token.startswith('--') and '=' in token else [token])
    if len(expanded) % 2:
        raise ValueError('Each extra option requires a value')
    fields, extras, seen = {}, [], set()
    for flag, value in zip(expanded[::2], expanded[1::2]):
        if flag in NUMBERS:
            name, low, high = NUMBERS[flag]
            if not value.isascii() or not value.isdigit() or not low <= int(value) <= high:
                raise ValueError('Invalid value for ' + flag)
            value = str(int(value))
        elif flag in ('-fa', '--flash-attn'):
            name = '--flash-attn'
            if value not in ('on', 'off', 'auto'):
                raise ValueError('Flash attention must be on, off, or auto')
        else:
            raise ValueError('Unsupported or Locard-owned extra option: ' + flag)
        if name in seen:
            raise ValueError('Duplicate extra option: ' + name)
        seen.add(name)
        if name in ('context', 'gpu_layers'):
            fields[name] = int(value)
        else:
            extras.extend((name, value))
    return fields, extras


def validate(tokens):
    if type(tokens) is not list or any(type(t) is not str for t in tokens):
        raise ValueError('Invalid stored extra options')
    fields, canonical = parse(' '.join(tokens))
    if fields or canonical != tokens:
        raise ValueError('Stored extra options must be canonical')
    return tokens
