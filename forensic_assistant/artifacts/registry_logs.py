"""Filename-designated Registry companions; no replay or content validation."""
from pathlib import Path

LIMITATION = 'Registry transaction-log replay is not supported; companion was not parsed as a hive'
CLASSIFIER = 'locard-registry-companion-classifier'


def is_log(path):
    return Path(path).suffix.casefold() in ('.log1', '.log2')


def describe(path):
    path = Path(path)
    candidates = []
    # This is only a possible filename relationship, never proof of hive identity.
    # Do not follow links or search outside the supplied file's directory.
    for sibling in path.parent.iterdir():
        if sibling.name.casefold() != path.stem.casefold() or sibling.is_symlink() or not sibling.is_file():
            continue
        with sibling.open('rb') as stream:
            if stream.read(4) == b'regf':
                candidates.append(str(sibling))
    return dict(classification='registry_transaction_log',
                classification_basis='Filename suffix .LOG1/.LOG2; log contents not validated',
                companion_hive=candidates[0] if len(candidates) == 1 else None,
                companion_basis='Possible companion by same-directory case-insensitive filename; not verified'
                if len(candidates) == 1 else 'Unmatched or ambiguous companion filename',
                limitation=LIMITATION, replay_performed=False)
