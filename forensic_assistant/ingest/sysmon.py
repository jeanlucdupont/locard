"""Field-specific Sysmon FileCreate semantics; never a generic UTC assumption."""
import re
from forensic_assistant.model import utc_timestamp


def is_file_create(event):
    return (event.get('provider') == 'Microsoft-Windows-Sysmon'
            and event.get('channel') == 'Microsoft-Windows-Sysmon/Operational'
            and event.get('event_id') == 11)


def file_create_timestamps(event, data):
    if not is_file_create(event):
        return
    for field, meaning in (
        ('UtcTime', 'Sysmon-reported event time'),
        ('CreationUtcTime', 'Sysmon-reported target-file creation timestamp'),
    ):
        original = data.get(field)
        # Duplicate fields have already been suppressed by the caller.
        if original in (None, '', '-'):
            continue
        match = re.fullmatch(r'\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.(\d{1,9}))?', original)
        # Only the documented timezone-free field format receives UTC semantics.
        value, status = utc_timestamp(original + 'Z' if match else original)
        fraction = re.search(r'\.(\d{1,9})(?:Z|[+-]\d\d:\d\d)?$', original)
        precision = 10 ** (9 - len(fraction[1])) if fraction else 1_000_000_000
        yield dict(slot='Sysmon.' + field, timestamp_utc=value, original_value=original,
                   encoding='Sysmon UTC text', source='Sysmon EventData ' + field,
                   meaning=meaning, precision_ns=precision if status == 'normalized' else None,
                   normalization_status=status)
