"""Plain-cell layout before centralized styling; escaped values have stable widths."""
import shutil
from .presentation import safe


def terminal_width(width=None):
    return max(20,width or shutil.get_terminal_size(fallback=(80,24)).columns)


def fit(text,width):
    return text if len(text)<=width else text[:max(0,width-3)]+'...'


def table(headers,rows,palette,*,minimums,maximums,roles,right=(),width=None):
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
    def rowline(row,header=False):
        return '  '.join(palette('key' if header else roles[i],
                               fit(value,sizes[i]).rjust(sizes[i]) if i in right else fit(value,sizes[i]).ljust(sizes[i]))
                         for i,value in enumerate(row))
    return [rowline(headers,True),'  '.join('-'*n for n in sizes),*[rowline(r) for r in cells]]
