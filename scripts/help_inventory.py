"""Provider-free inventory of canonical argparse help; advisory editorial warnings."""
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forensic_assistant.cli import build_parser


def collect():
    rows = []
    def walk(parser, path):
        rows.append(dict(path=path, item='[command]', text=parser.description or '', kind='command'))
        for action in parser._actions:
            if action.help == argparse.SUPPRESS:
                continue
            rows.append(dict(path=path, item=' / '.join(action.option_strings) or action.dest,
                             text=action.help or '', kind='argument',
                             structural=isinstance(action, argparse._SubParsersAction)))
            if isinstance(action, argparse._SubParsersAction):
                for choice in action._choices_actions:
                    rows.append(dict(path=path, item='[subcommand] '+choice.dest, text=choice.help or '', kind='command'))
                for name, child in action.choices.items():
                    walk(child, (path+' '+name).strip())
        if parser.epilog:
            rows.append(dict(path=path, item='[footer]', text=parser.epilog, kind='footer'))
    walk(build_parser(interactive=True), '')
    return rows


def concerns(row):
    # Editorial triage only, never runtime semantics or a reason to remove a constraint.
    text = (row['path']+' '+row['item']+' '+row['text']).lower()
    categories = {'authorization': ('approve','authoriz','confirm','execute'),
                  'external disclosure': ('cloud','provider','transmission'),
                  'forensic meaning': ('evidence','source','timestamp','ground','coverage','hypothes','provenance'),
                  'mutation/integrity': ('overwrite','replace','force','clone','register','replay','integrity','audit')}
    return ', '.join(k for k, terms in categories.items() if any(t in text for t in terms)) or 'routine'


def quality(rows):
    return [dict(path=r['path'], item=r['item'], issue='empty' if not r['text'] else 'long: review safety context')
            for r in rows if not r.get('structural') and (not r['text'] or len(r['text'].split())>30)]


def comparison(before, after):
    def key(r): return r['path'], r['item']
    old, new = {key(r):r for r in before}, {key(r):r for r in after}
    def cell(value):return str(value).replace('|','\\|').replace('\n','<br>')
    lines = ['# Locard 6.147 help editorial inventory', '',
             'Generated from canonical interactive parser metadata. Length is characters / words. Safety categories are advisory triage, not authorization decisions.', '',
             '| Command | Entry | Previous | Revised | Old length | New length | Changed | Review category |',
             '|---|---|---|---|---|---|---|---|']
    for k in sorted(old.keys()|new.keys()):
        a,b=old.get(k,{}).get('text',''),new.get(k,{}).get('text','')
        row=new.get(k,old.get(k))
        values=[k[0] or '(root)',k[1],a,b,f'{len(a)} / {len(a.split())}',f'{len(b)} / {len(b.split())}',str(a!=b),concerns(row)]
        lines.append('| '+' | '.join(map(cell,values))+' |')
    lines += ['', '## Advisory quality flags', '', 'Long safety explanations are intentionally permitted. Structural subparser placeholders need no duplicate description.', '']
    lines += ['- `'+r['path']+' '+r['item']+'`: '+r['issue'] for r in quality(after)]
    return '\n'.join(lines)+'\n'


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--before',type=Path)
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    rows=collect()
    text=comparison(json.loads(args.before.read_text(encoding='utf-8')),rows) if args.before else json.dumps(dict(entries=rows,quality_flags=quality(rows)),indent=2)
    if args.output:args.output.write_text(text,encoding='utf-8')
    else:print(text)
