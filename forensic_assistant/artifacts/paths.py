"""Comparison only: never consult the analyst filesystem or environment."""
import ntpath
import re


def normalize_path(value):
    text = str(value)
    warnings = []
    if text!=text.strip():warnings.append('Surrounding whitespace retained; object identity unresolved')
    if text.startswith('"') and text.endswith('"') and text.count('"') == 2:
        text = text[1:-1]
    text = text.replace('/', '\\')
    if text.lower().startswith(('\\\\?\\unc\\','\\??\\unc\\')): text = '\\\\' + text[8:]
    elif text.startswith(('\\\\?\\','\\??\\')): text = text[4:]
    kind = 'absolute' if re.match(r'^[a-zA-Z]:\\',text) or text.startswith('\\\\') else 'relative'
    if text.lower().startswith('\\device\\'): kind = 'device'
    elif re.search(r'%[^%]+%',text) or text.lower().startswith('\\systemroot\\'): kind = 'unexpanded'
    elif text.startswith('\\') and kind != 'absolute': kind = 'volume_relative'
    if '..' in text.split('\\'): warnings.append('Parent traversal retained; object identity unresolved')
    if '~' in text: warnings.append('Short-name alias not resolved')
    # Preserve dot components, trailing spaces/dots, streams, and device distinctions.
    normalized = text.lower() if not warnings else None
    return dict(original=value,normalized=normalized,basename=ntpath.basename(text).lower(),kind=kind,warnings=warnings)


def executable_reference(value):
    """Extract only an unambiguous executable token; no shell evaluation."""
    text = value.strip()
    if text.startswith('"'):
        end = text.find('"',1)
        return text[1:end] if end > 1 else None
    token = text.split()[0] if text else ''
    if re.search(r'\.(exe|com|bat|cmd|ps1|vbs|js)$',token,re.I): return token
    return text if text and not re.search(r'\s',text) else None
