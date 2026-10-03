"""Non-fatal EVTX identifier validation stored in existing warning arrays."""
import re

LABEL = 'EVTX record-header identifier differs from XML EventRecordID'
_PATTERN = re.compile(re.escape(LABEL) + r': header=[0-9]+; xml=[0-9]+; offset=(?:[0-9]+|None)\Z')


def identifier_note(header, xml, offset):
    return f'{LABEL}: header={header}; xml={xml}; offset={offset}'


def is_identifier_note(value):
    return isinstance(value, str) and _PATTERN.fullmatch(value) is not None
