"""Source-span candidates for narrative paths and explicitly delimited filenames."""
from dataclasses import dataclass
import re
from bisect import bisect_right

EXT = r'(?:exe|ps1|bat|cmd|lnk|zip|docx?|xlsx?|pdf|dll|js|vbs|msi|wsc)'
PATH_START = re.compile(r'(?:[A-Za-z]:\\|\\\\)')
END_FILE = re.compile(r'(?i)\.'+EXT+r'(?=$|[\s,.;)\]}])')
DELIMITED = re.compile(r'"([^"\r\n]+)"|\x27([^\x27\r\n]+)\x27|\(([^()\r\n]+)\)')
BARE_FILE = re.compile(r'(?i)(?<![\w.\[\]-])[\w][\w.\[\]-]{0,180}\.'+EXT+r'(?!\w|\.\w)')


@dataclass
class Candidate:
    start: int
    end: int
    classification: str = 'exact'
    def span(self, group=0):return self.start,self.end


class SpanIndex:
    def __init__(self, spans):
        ordered=sorted(spans,key=lambda c:c.start)
        self.starts=[];self.ends=[];end=-1
        for span in ordered:
            self.starts.append(span.start);end=max(end,span.end);self.ends.append(end)


def contained(a,b,spans):
    if isinstance(spans,SpanIndex):
        index=bisect_right(spans.starts,a)-1
        return index>=0 and spans.ends[index]>=b
    return any(x.start<=a and b<=x.end for x in spans)


def candidates(text):
    paths=[];files=[]
    for match in PATH_START.finditer(text):
        a=match.start()
        if paths and contained(a,match.end(),paths[-1:]):continue
        quote=text[a-1] if a and text[a-1] in ('"',"'") else None
        if quote:
            end=text.find(quote,a)
            if end!=-1 and '\n' not in text[a:end] and '\r' not in text[a:end]:
                paths.append(Candidate(a,end,'ambiguous' if re.search(r'[<>|?*]',text[a:end]) else 'exact'));continue
        boundary=re.search(r'[\r\n"<>|?*]',text[a:a+241])
        end=a+boundary.start() if boundary else len(text)
        end=min(end,a+240)
        candidate=text[a:end]
        chosen=None; uncertain=False
        for suffix in END_FILE.finditer(candidate):
            tail=candidate[suffix.end():]
            # A recognized file extension plus punctuation/end or a clear prose
            # boundary. Spaces in directory and filename components are retained.
            if not tail.strip() or tail[:1] in ',.;)]}' or re.match(r'(?i)\s+(?:was|were|is|has|had|wasn\x27t|and|but|then)\b',tail):
                chosen=a+suffix.end();break
            uncertain=True
        if chosen is not None:
            paths.append(Candidate(a,chosen,'ambiguous' if quote or uncertain else 'exact'))
        else:
            trimmed=candidate.rstrip(' \t,.;)')
            if len(trimmed)>match.end()-a:paths.append(Candidate(a,a+len(trimmed),'ambiguous'))
    path_index=SpanIndex(paths)
    for match in DELIMITED.finditer(text):
        group=next(i for i in (1,2,3) if match.group(i) is not None)
        a,b=match.span(group);value=text[a:b]
        if contained(a,b,path_index) or re.search(r'[\\/:<>|?*]',value):continue
        if re.fullmatch(r'(?i)[^\r\n]{1,240}\.'+EXT,value):files.append(Candidate(a,b))
    occupied=SpanIndex(paths+files)
    for match in BARE_FILE.finditer(text):
        a,b=match.span()
        if not contained(a,b,occupied):files.append(Candidate(a,b))
    return paths,sorted(files,key=lambda c:c.start)
