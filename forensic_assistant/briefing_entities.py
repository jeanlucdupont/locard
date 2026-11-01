"""Conservative entity candidates in analyst prose, never verified identities."""
import re
from .briefing_boundaries import Candidate

# Case-sensitive capitalization is intentional; IGNORECASE belongs on labels only.
NAME = r"[A-Z\u00c0-\u00d6\u00d8-\u00de][a-z\u00e0-\u00f6\u00f8-\u00ff]+(?:[-'][A-Z\u00c0-\u00d6\u00d8-\u00de]?[a-z\u00e0-\u00f6\u00f8-\u00ff]+)*"
PERSON = NAME + r"(?: " + NAME + r"){1,3}"
ACCOUNT = r"[A-Za-z][\w.-]{0,63}\\[A-Za-z][\w.-]{0,63}|[A-Za-z][\w.-]{0,63}@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}"
HOST = r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?"
LABEL = r"(?i:hostname|host|computer|machine|workstation|device|laptop|server)"
PROSE = {'a', 'an', 'per-user', 'type-library', 'follow-on', 'follow-up', 'command-line',
         'process-creation', 'read-only', 'unknown', 'unavailable', 'affected',
         'was', 'is', 'named', 'the', 'not', 'reported', 'it', 'this', 'that', 'which', 'name', 'broken', 'involved', 'compromised', 'infected',
         'offline', 'online', 'running'}
USER_PROSE = {'tried', 'reported', 'was', 'is', 'has', 'had', 'did', 'opened',
              'clicked', 'logged', 'received', 'downloaded', 'unknown', 'not',
              'the', 'com', 'type', 'activity', 'account', 'user', 'name',
              'windows', 'microsoft', 'defender', 'powershell', 'registry'}


def valid_host(value):
    return (len(value) <= 253 and value.casefold() not in PROSE and
            all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', part)
                for part in value.split('.')) and not value.isdigit())


def machine_like(value):
    # Digit-bearing machine labels are useful without context. Algorithm names
    # such as SHA-256/UTF-8 are not machine identifiers.
    return (valid_host(value) and '-' in value and bool(re.search(r'\d', value))
            and not re.match(r'(?i)^(?:sha|utf|aes|rsa|iso|windows)-', value))


def candidates(text):
    users = {}; hosts = {}
    def user(match):
        a, b = match.span('value')
        value = text[a:b]
        if any(word.casefold() in USER_PROSE for word in value.split()):
            return
        prefix=text[match.start():a].casefold()
        if ' ' not in value and not re.fullmatch(ACCOUNT,value) and value[0].islower():
            if not re.search(r'username|account|named|[:=]',prefix):return
        users[a,b] = Candidate(a,b)
    for pattern in (
        r'(?<![\w-])(?i:user(?:name)?(?: named)?|account)\s*(?:[:=]\s*|\s+)(?P<value>' + ACCOUNT + '|' + PERSON + r'|[A-Za-z][\w.-]{0,63})(?![\w\\-])',
        r'(?<![\w-])(?P<value>' + PERSON + r')(?=\s+(?i:tried|reported|received|downloaded|opened|clicked|logged)\b)',
    ):
        for match in re.finditer(pattern, text):user(match)
    # Explicit labels support short hostnames; ordinary hyphenated words alone
    # do not. Retain source offsets instead of rewriting the analyst's text.
    for match in re.finditer(r'(?<![\w-])' + LABEL + r'\s*(?:(?i:is|was|named)\s+|[:=]\s*|\s+)["\']?(?P<value>' + HOST + r')', text):
        a,b=match.span('value')
        while b>a and text[b-1]=='.':b-=1
        if valid_host(text[a:b]) and not re.match(r'(?i)\s+(?:laptop|computer|workstation|server)\b',text[b:b+20]):hosts[a,b]=Candidate(a,b)
    for match in re.finditer(r'(?<![\w.-])[A-Za-z][A-Za-z0-9-]{1,62}(?![\w.-])', text):
        if machine_like(match.group()):hosts[match.span()]=Candidate(*match.span())
    return list(users.values()), list(hosts.values())


def answer_host(text, question):
    """Question supplies a type only, never a value; require a whole-token answer."""
    if not re.fullmatch(r"(?i)\s*(?:what is|do you know) (?:the )?(?:computer(?:'s)? name|hostname|host name|machine(?:'s)? name)\?\s*",question):
        return None
    value=text.strip()
    if not valid_host(value):return None
    a=len(text)-len(text.lstrip())
    return Candidate(a,a+len(value))


def source_questions(content):
    return {f"interview:{session['id']}:{i+1}":turn['question']
            for session in content.get('interviews',[]) for i,turn in enumerate(session['turns'])}
