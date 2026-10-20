"""Explicit session-only diagnostics. No filesystem writes or prompt capture."""
from collections import deque
import os
import re

WARNING = 'Raw AI diagnostics may contain case evidence, filenames, host/user identifiers, and model-generated content.'
LIMIT = 16384
_entries = deque(maxlen=10)
enabled = False
sink = None

def clear():
    global enabled, sink
    sink = None
    _entries.clear()
    enabled = False

def sanitize(text):
    # Redact secret-bearing environment values and known credential formats.
    for value in sorted({v for k,v in os.environ.items() if re.search(r'(?i)(key|token|secret|password|credential|authorization|cookie)',k)},key=len,reverse=True):
        if value: text=text.replace(value,'[REDACTED]')
    text=re.sub(r'(?i)(?:authorization|proxy-authorization|x-api-key|api-key|cookie|set-cookie)[\"\']?\s*[:=][^\r\n]*','[REDACTED HEADER]',text)
    text=re.sub(r'(?:sk-[A-Za-z0-9_-]+|AIza[A-Za-z0-9_-]+)','[REDACTED KEY]',text)
    return text

def entry(kind,text):
    if kind not in ('raw_model_output','raw_provider_error') or type(text) is not str:return None
    # Redact before truncation so a cut secret cannot escape matching.
    text=sanitize(text)
    raw=text.encode('utf-8',errors='replace')
    return {'kind':kind,'text':raw[:LIMIT].decode('utf-8',errors='ignore'),'truncated':len(raw)>LIMIT}

def capture(value):
    if not enabled or type(value) is not dict:return
    item=entry(value.get('kind'),value.get('text'))
    if item:
        item['truncated'] |= value.get('truncated') is True
        if sink is not None: sink(item)
        else: _entries.append(item)

def display():
    global enabled
    enabled=True
    rows=[WARNING,'RAW AI DIAGNOSTIC OUTPUT — NOT EVIDENCE']
    if not _entries:rows.append('Capture enabled for subsequent cloud requests in this process. No buffered output is available.')
    while _entries:
        item=_entries.popleft()
        rows.extend((item['kind'],sanitize(item['text'])))
        if item['truncated']:rows.append('[TRUNCATED]')
    return '\n'.join(rows)
