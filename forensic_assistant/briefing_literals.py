"""Source-supported concrete literals, separate from generic investigation wording."""
import ipaddress
import re

TECHNICAL = frozenset(('timestamp','date','event_id','windows_path','registry_path','hash',
                      'ipv4','ipv6','filename','domain','hostname','username'))
# Narrow, demonstrated linguistic collisions, not a blanket hostname exemption.
CONCEPTS = frozenset(('command-line','process-creation','follow-up'))


def literals(text):
    from .briefing import extract
    result = set()
    if not text.lstrip('\ufeff').strip():
        return result
    for lead in extract(text)['leads']:
        kind = lead['type']
        if kind not in TECHNICAL:
            continue
        for occurrence in lead['occurrences']:
            before = text[max(0,occurrence['start']-60):occurrence['start']]
            after = text[occurrence['end']:occurrence['end']+1]
            if kind=='hostname' and lead['normalized'] in CONCEPTS:
                attributed = re.search(r'(?i)\b(?:host(?:name)?|computer|machine|server)(?:\s+named)?\s*[:=]?\s*["\x27`]?$',before)
                quoted = before.endswith(('"',"'",'`')) or after in ('"',"'",'`')
                if not attributed and not quoted:
                    continue
            if kind=='username' and re.search(r'(?i)\buser\s+$',before) and re.match(r'(?i)^activity\b',occurrence['original']):
                continue
            value = str(lead['normalized'])
            if kind=='registry_path':value=value.casefold()
            # End-of-sentence punctuation is not part of an unquoted path/key.
            if kind in ('windows_path','registry_path') and not before.endswith(('"',"'",'`')):
                value=value.rstrip('.,;!?')
            result.add((kind,value))
    # Preserve source extraction/lead IDs; supplement only literal reconciliation.
    for match in re.finditer(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\d)',text):
        try: result.add(('ipv4',str(ipaddress.ip_address(match.group()))))
        except ValueError: result.add(('ipv4',match.group()))
    for match in re.finditer(r'(?i)\bEvent\s+(?:ID\s+)?(\d{1,6})\b',text):
        result.add(('event_id',str(int(match[1]))))
    # Exact command-like interpreter invocations remain concrete, even in questions.
    for match in re.finditer(r'(?i)\b(?:powershell|pwsh|cmd|wscript|cscript)(?:\.exe)?\s+[-/][^\r\n"`?]{1,240}',text):
        result.add(('command_line',match.group().rstrip(' .;').casefold()))
    return result


def claims_proof(text):
    # Narrow affirmative event-ID proof claim; not general semantic entailment.
    return bool(re.search(r'(?i)(?:^|[.!?]\s+)(?:Defender\s+)?Event\s+(?:ID\s+)?\d+\s+'
                          r'(?:confirms|proves|establishes)\s+(?:successful\s+)?(?:execution|compromise|causation)\b',text))


def unsupported(text, inputs, units):
    """Reassemble adjacent cited chunks; never invent support across a source gap."""
    allowed=set();groups=[]
    for unit in sorted(units,key=lambda u:(u['source'],u['start'])):
        if groups and groups[-1][0]==unit['source'] and groups[-1][2]==unit['start']:
            groups[-1]=(groups[-1][0],groups[-1][1],unit['end'])
        else:groups.append((unit['source'],unit['start'],unit['end']))
    for source,start,end in groups:
        allowed.update(literals(inputs[source][start:end]))
    return literals(text)-allowed
