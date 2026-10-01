import copy
import json
import os
from contextlib import contextmanager
from types import SimpleNamespace
import pytest
from forensic_assistant.cli import main, build_parser
from forensic_assistant import v2_cli, terminal, output
from forensic_assistant.database.db import connect
from forensic_assistant.retrieval.around_display import render, delta
from test_output_ux import case, Terminal


def example():
    a = dict(id='PREFETCH:'+'a'*64+':File', source_type='prefetch', artifact_type='prefetch_file',
             objects=[dict(role='executable', original='POWERSHELL.EXE')], context={},
             timestamps=[dict(slot='run:1', timestamp_utc='2020-01-01T00:00:00.000000001Z'),
                         dict(slot='run:2', timestamp_utc='2020-01-01T00:00:00.000000002Z')])
    rows = [dict(a, timestamp_utc=t['timestamp_utc'], timestamp=dict(t,source='Prefetch LastRun',meaning='execution')) for t in a['timestamps']]
    return a, dict(records=rows,total=2,offset=0,truncated=False), SimpleNamespace(timestamp_slot='run:2', seconds=60,direction='around',ids=False)


def test_exact_slot_delta_ids_and_immutable_data():
    a,r,args=example(); before=copy.deepcopy(r)
    text=render(r,a,a['timestamps'][1]['timestamp_utc'],args,width=120)
    assert '-0.000000001s' in text and '0.000s' in text
    assert text.count('<- anchor')==1 and a['id'] not in text
    assert 'Prefetch' in text and 'prefetch_file' not in text
    args.ids=True
    assert render(r,a,a['timestamps'][1]['timestamp_utc'],args).count(a['id'])==2
    assert r==before


@pytest.mark.parametrize('stamp,expected',[
    ('2019-12-31T23:59:59.999999999Z','-0.000000001s'),
    ('2020-01-01T00:00:07.187000000Z','+7.187s'),
    ('2020-01-01T00:00:00.000000000Z','0.000s')])
def test_delta(stamp,expected):
    assert delta(stamp,'2020-01-01T00:00:00.000000000Z')==expected


@pytest.mark.parametrize('direction,label',[('around','+/-60s around'),('before','60s before'),('after','60s after')])
def test_direction_heading(direction,label):
    a,r,args=example();args.direction=direction
    assert render(r,a,a['timestamps'][1]['timestamp_utc'],args,width=120).startswith(
        f'Temporal context: {label} POWERSHELL.EXE\n')


def test_mixed_narrow_color_and_untrusted_text():
    a,r,args=example()
    r['records'][1]=dict(r['records'][1],source_type='registry',artifact_type='registry_key',
                        objects=[dict(role='key',original='X'*100+'\x1b[31m')],
                        timestamp=dict(r['records'][1]['timestamp'],source='Registry LastWrite',meaning='key modification'))
    plain=render(r,a,a['timestamps'][1]['timestamp_utc'],args,width=40)
    colored=render(r,a,a['timestamps'][1]['timestamp_utc'],args,terminal.Palette(True),width=40)
    assert terminal.SGR.sub('',colored)==plain
    assert max(map(len,plain.splitlines()))<=40 and '...' in plain
    assert 'Registry key' in plain and 'Prefetch' in plain
    assert 'key modification' in plain and 'execution' in plain
    assert '\x1b' not in plain


def test_ambiguous_slots_are_not_arbitrarily_marked():
    a,r,args=example();args.timestamp_slot=None
    a['timestamps'][1]['timestamp_utc']=a['timestamps'][0]['timestamp_utc']
    text=render(r,a,a['timestamps'][0]['timestamp_utc'],args,width=120)
    assert 'ambiguous' in text and '<- anchor' not in text


def test_sources_midnight_and_empty_page():
    a,r,args=example()
    for i,row in enumerate(r['records']):
        row['context']={'source_assertions':[dict(display_name='Same label',source_id=f'src-{i}')]}
    r['records'][0]['timestamp_utc']='2019-12-31T23:59:59.999999999Z'
    text=render(r,a,a['timestamps'][1]['timestamp_utc'],args,width=120)
    assert 'Source (displayed rows)' not in text
    assert 'src-0' in text and 'src-1' in text
    assert '2019-12-31' in text and '2020-01-01' in text and '-0.000000003s' in text
    r.update(records=[],offset=2)
    text=render(r,a,a['timestamps'][1]['timestamp_utc'],args,width=120)
    assert 'Displayed 0 / 2' in text and '<- anchor' not in text


def test_around_colored_pager(case,monkeypatch):
    stream=Terminal()
    monkeypatch.setattr(output.sys,'stdout',stream)
    monkeypatch.setattr(output.sys,'stdin',Terminal())
    monkeypatch.setattr(output.shutil,'get_terminal_size',lambda **kw:os.terminal_size((40,6)))
    monkeypatch.setattr(terminal,'capable',lambda stream:True)
    monkeypatch.delenv('NO_COLOR',raising=False)
    restored=[]
    @contextmanager
    def keyboard():
        try:yield lambda:'q'
        finally:restored.append(True)
    monkeypatch.setattr(output,'keyboard',keyboard)
    assert main(['--db',str(case[0]),'around',case[1],'--timestamp-slot','run:1','--text','--page'])==0
    text=stream.getvalue()
    assert '\x1b[' in text and '-- More --' in text and restored==[True]
    assert len(terminal.SGR.sub('',text).split('-- More --')[0].splitlines())==4


def test_cli_selection_json_raw_page_files(case,tmp_path,capsys,monkeypatch):
    path,eid,_=case
    base=['--db',str(path),'around',eid,'--timestamp-slot','run:1','--seconds','604800']
    before=path.read_bytes()
    with connect(path) as db:
        expected,_=v2_cli.dispatch(db,build_parser().parse_args(base))
    assert main(base+['--json'])==0
    assert json.loads(capsys.readouterr().out)==expected
    assert main(base+['--text'])==0
    text=capsys.readouterr().out
    assert 'Displayed 2 / 2' in text and eid not in text and text.count('<- anchor')==1
    assert main(base+['--text','--ids'])==0
    assert eid in capsys.readouterr().out
    assert main(base+['--text','--page'])==0
    assert capsys.readouterr().out==text
    target=tmp_path/'context.txt'
    monkeypatch.setattr(terminal,'capable',lambda stream:True)
    for flag in ('--output','--append'):
        assert main(base+['--text',flag,str(target)])==0
    exported=target.read_text(encoding='utf-8')
    assert exported==text+'\n'+text and '\x1b' not in exported
    capsys.readouterr()
    assert main(base+['--raw','--json'])==0
    raw=json.loads(capsys.readouterr().out)
    assert raw['records'][0]['id']==eid and raw['records'][0]['detail']['raw_file']['encoding']=='base64'
    assert main(base+['--raw','--text','--no-color'])==0
    assert capsys.readouterr().out==v2_cli.render(raw)+'\n'
    assert path.read_bytes()==before
