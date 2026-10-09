"""Plain-cell layout before centralized styling; escaped values have stable widths."""
import shutil
import re
from .presentation import safe, safe_path


def terminal_width(width=None):
    return max(20, width or shutil.get_terminal_size(fallback=(80, 24)).columns)


def fit(text, width):
    return text if len(text) <= width else text[:max(0, width - 3)] + '...'


def fit_path(text, width, *, literal=False):
    """Shorten an already safe()-escaped path at separator boundaries.

    Preserve the literal suffix, including separator style. If even the final
    component cannot fit, visibly shorten that component as a last resort.
    """
    if len(text) <= width:
        return text
    separators = list(re.finditer(r'\\+|/' if literal else r'\\\\|/', text))
    for match in separators:
        suffix = '...' + text[match.start():]
        if len(suffix) <= width:
            return suffix
    if separators:
        last = separators[-1]
        prefix = '...' + last.group()
        if width >= len(prefix) + 4:
            return prefix + fit(text[last.end():], width - len(prefix))
    return fit(text, width)


def pagination(count, total, offset=0):
    if count == total and offset == 0:
        return ''
    if not offset or not count:
        return f'Showing {count} of {total}'
    return f'Showing {offset+1}\u2013{offset+count} of {total}'


def table(headers, rows, palette, *, minimums, maximums, roles, right=(), width=None, tail=(), format_cell=None, paths=(), text=safe, after_row=None):
    width = terminal_width(width)
    cells = [[(safe_path if i in paths else text)(value) for i, value in enumerate(row)] for row in rows]
    sizes = [max(len(h), min(maximums[i], max([len(h)] + [len(r[i]) for r in cells]))) for i, h in enumerate(headers)]
    while sum(sizes) + 2 * (len(sizes) - 1) > width:
        candidates = [i for i, n in enumerate(sizes) if n > max(minimums[i], len(headers[i]))]
        if not candidates:
            break
        i = max(candidates, key=lambda i: sizes[i])
        sizes[i] -= 1
    if sum(sizes) + 2 * (len(sizes) - 1) > width:
        lines = []
        for row_index, row in enumerate(cells):
            if lines:
                lines.append('')
            for i, value in enumerate(row):
                available = max(3, width - len(headers[i]) - 2)
                shown = format_cell(row_index, i, value, available) if format_cell else None
                if shown is None:
                    shown = fit_path(value, available, literal=i in paths) if i in tail else fit(value, available)
                lines.append(palette('key', headers[i] + ': ') + palette(roles[i], shown))
            if after_row:
                lines.extend(after_row(row_index))
        return lines
    def cell(value, i, header, row_index):
        shown = format_cell(row_index, i, value, sizes[i]) if format_cell and not header else None
        if shown is None:
            shown = fit_path(value, sizes[i], literal=i in paths) if not header and i in tail else fit(value, sizes[i])
        return shown.rjust(sizes[i]) if i in right else shown.ljust(sizes[i])
    def rowline(row, header=False, row_index=0):
        return '  '.join(
            palette(
                'key' if header else roles[i],
                cell(value, i, header, row_index)
            )
            for i,
            value in enumerate(row)
        )
    lines = [rowline(headers, True), '  '.join('-' * n for n in sizes)]
    for n, row in enumerate(cells):
        lines.append(rowline(row, row_index=n))
        if after_row:
            lines.extend(after_row(n))
    return lines
