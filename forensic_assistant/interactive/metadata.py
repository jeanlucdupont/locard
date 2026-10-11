"""Interactive source-field entry; shared provenance validation stays authoritative."""
from forensic_assistant.artifacts.context import normalize_volume_root


def read_volume_root(read, prompt, palette):
    while True:
        value = read(prompt).strip()
        # A lone ASCII drive letter is unambiguous examiner input, not inference.
        if len(value) == 1 and value in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz':
            value += ':'
        try:
            return normalize_volume_root(value)
        except ValueError:
            print(palette('error', 'Please enter a drive letter followed by a colon, for example C:.'))
