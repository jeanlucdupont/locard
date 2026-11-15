"""Analyst CLI input only; never normalize persisted/signed forensic content here."""
import re
from datetime import datetime, timezone


def absolute_utc(value):
    """Expand ISO shorthand and normalize through an aware UTC datetime.

    Keep up to nine original fractional digits separately from datetime's
    microsecond precision. Downstream validators retain their existing bounds.
    """
    match = re.fullmatch(r'(\d{4}-\d{2}-\d{2})(?:[T ](\d{2})(?::(\d{2})(?::(\d{2})(\.\d{1,9})?)?)?)?(Z|[+-]\d{2}:\d{2})?', value)
    if not match:
        raise ValueError('Use an ISO date/time with optional UTC offset; omitted time/timezone means midnight/UTC.')
    date,hour,minute,second,fraction,offset = match.groups()
    if offset and offset != 'Z' and (int(offset[1:3])>23 or int(offset[4:])>59):
        raise ValueError('Invalid UTC offset')
    try:
        dt = datetime.fromisoformat(date+'T'+(hour or '00')+':'+(minute or '00')+':'+(second or '00')+
                                    ('+00:00' if offset in (None,'Z') else offset)).astimezone(timezone.utc)
    except (ValueError,OverflowError) as exc:
        raise ValueError('Invalid absolute date/time') from exc
    return dt.isoformat(timespec='seconds').removesuffix('+00:00') + (fraction or '') + 'Z'


def normalize_arguments(args):
    # Only analyst-entered CLI absolute filter fields, before service validation.
    names = ['start','end','since']
    if getattr(args,'command',None)=='timeline': names += ['timestamp','around']
    for name in names:
        value = getattr(args,name,None)
        if isinstance(value,str): setattr(args,name,absolute_utc(value))
    return args
