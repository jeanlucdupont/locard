"""Offline HTML and Markdown projections of one human report view."""
import html
import re
from . import view
from .legacy_render import CSS


def esc(value):
    return html.escape(str(value), quote=True)


def md(value):
    # Evidence cannot introduce HTML, links, headings, images or table structure.
    value = html.escape(str(value), quote=True)
    value = re.sub(r'([\\`*_{}\[\]()#!|])', r'\\\1', value).replace('\n', ' ')
    value = re.sub(r'^([+-])(?= )', r'\\\1', value)
    return re.sub(r'^(\d+)\.(?= )', r'\1\\.', value)


def render(report):
    if 'presentation_format' not in report:
        from .legacy_render import render as legacy
        return legacy(report)
    model = view.build(report)
    out = ['<!doctype html><html lang="en"><head><meta charset="utf-8">',
           '<meta name="viewport" content="width=device-width, initial-scale=1">',
           '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">',
           '<title>' + esc(model['title']) + '</title><style>' + CSS +
           'td,th{overflow-wrap:anywhere}table{table-layout:fixed}details{margin:12px 0}@media print{details{display:block}}</style></head><body><main>',
           '<div class="label">LOCARD · DERIVED FORENSIC REPORT</div><h1>' + esc(model['title']) + '</h1>',
           '<p class="muted">' + esc(model['identity']) + '</p>',
           '<p>Status: <strong>' + esc(model['status']) + '</strong>. Completion applies to this bounded report only.</p>']
    for section in model['sections']:
        anchor = ' id="' + esc(section['anchor']) + '"' if section['anchor'] else ''
        out += ['<section' + anchor + '><h2>' + esc(section['title']) + '</h2>']
        for kind, body in section['blocks']:
            if kind == 'paragraph':
                out.append('<p>' + esc(body) + '</p>')
            elif kind == 'heading':
                out.append('<h3>' + esc(body) + '</h3>')
            elif kind == 'bullets':
                out.append('<ul>' + ''.join('<li>' + esc(item) + '</li>' for item in body) + '</ul>')
            elif kind == 'details':
                out.append('<details><summary>' + esc(body[0]) + '</summary><ul>' + ''.join('<li>' + esc(item) + '</li>' for item in body[1]) + '</ul></details>')
            elif kind == 'table':
                headers, rows = body
                out.append('<table><thead><tr>' + ''.join('<th>' + esc(h) + '</th>' for h in headers) + '</tr></thead><tbody>' + ''.join('<tr>' + ''.join('<td>' + esc(cell) + '</td>' for cell in row) + '</tr>' for row in rows) + '</tbody></table>')
        out.append('</section>')
    out.append('</main></body></html>')
    return ''.join(out).encode('utf-8')


def markdown(report):
    model = view.build(report)
    out = ['# ' + md(model['title']), '', md(model['identity']), '',
           'Status: **' + md(model['status']) + '**. Completion applies to this bounded report only.', '']
    for section in model['sections']:
        out += ['## ' + md(section['title']), '']
        for kind, body in section['blocks']:
            if kind == 'paragraph':
                out += [md(body), '']
            elif kind == 'heading':
                out += ['### ' + md(body), '']
            elif kind == 'bullets':
                out += ['- ' + md(item) for item in body] + ['']
            elif kind == 'details':
                out += ['<details>', '<summary>' + esc(body[0]) + '</summary>', '']
                out += ['- ' + md(item) for item in body[1]] + ['', '</details>', '']
            elif kind == 'table':
                headers, rows = body
                out += ['| ' + ' | '.join(md(h) for h in headers) + ' |',
                        '| ' + ' | '.join('---' for _ in headers) + ' |']
                out += ['| ' + ' | '.join(md(cell) for cell in row) + ' |' for row in rows] + ['']
    return '\n'.join(out).encode('utf-8')
