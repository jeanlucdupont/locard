"""Plain-cell layout before centralized styling; escaped values have stable widths."""
import shutil
from .presentation import safe


def terminal_width(width=None):
    return max(20,width or shutil.get_terminal_size(fallback=(80,24)).columns)


def fit(text,width):
    return text if len(text)<=width else text[:max(0,width-3)]+'...'


def pagination(count,total,offset=0):
    if count==total and offset==0:return ''
    if not offset or not count:return f'Showing {count} of {total}'
    return f'Showing {offset+1}\u2013{offset+count} of {total}'


def table(headers,rows,palette,*,minimums,maximums,roles,right=(),width=None,tail=()):
    width=terminal_width(width)
    cells=[[safe(value) for value in row] for row in rows]
    sizes=[max(len(h),min(maximums[i],max([len(h)]+[len(r[i]) for r in cells]))) for i,h in enumerate(headers)]
    while sum(sizes)+2*(len(sizes)-1)>width:
        candidates=[i for i,n in enumerate(sizes) if n>max(minimums[i],len(headers[i]))]
        if not candidates:break
        i=max(candidates,key=lambda i:sizes[i]);sizes[i]-=1
    if sum(sizes)+2*(len(sizes)-1)>width:
        lines=[]
        for row in cells:
            if lines:lines.append('')
            for i,value in enumerate(row):
                lines.append(palette('key',headers[i]+': ')+palette(roles[i],fit(value,max(3,width-len(headers[i])-2))))
        return lines
    def cell(value,i,header):
        shown=('...'+value[-max(1,sizes[i]-3):]) if not header and i in tail and len(value)>sizes[i] else fit(value,sizes[i])
        return shown.rjust(sizes[i]) if i in right else shown.ljust(sizes[i])
    def rowline(row,header=False):
        return '  '.join(palette('key' if header else roles[i],
                               cell(value,i,header))
                         for i,value in enumerate(row))
    return [rowline(headers,True),'  '.join('-'*n for n in sizes),*[rowline(r) for r in cells]]
