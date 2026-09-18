"""Integer FILETIME normalization without loss of the 100ns source precision."""
from datetime import datetime, timedelta, timezone


def filetime(value, slot, source, meaning):
    result=dict(slot=slot, original_value=str(value) if value is not None else None, encoding='FILETIME',
                source=source, meaning=meaning, precision_ns=100, timestamp_utc=None,
                normalization_status='missing' if value in (None,0) else 'invalid')
    if value is not None and isinstance(value,int) and 0 < value < 2**64:
        try:
            seconds, ticks=divmod(value,10_000_000)
            dt=datetime(1601,1,1,tzinfo=timezone.utc)+timedelta(seconds=seconds)
            result.update(timestamp_utc=dt.strftime('%Y-%m-%dT%H:%M:%S')+f'.{ticks*100:09d}Z',normalization_status='normalized')
        except (ValueError,OverflowError):pass
    return result
