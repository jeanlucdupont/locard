"""6.92 rendering is pure: no queries, inference engine or provider calls."""
import copy
import io
import json
import time
import tracemalloc
import pytest
from forensic_assistant import assessment as a, assessment_display as d
from test_assessment import case, arguments, factory
from forensic_assistant import assessment_cli as cli
from forensic_assistant.assessment_store import AssessmentStore
from forensic_assistant.briefing_store import Store
from contextlib import closing
from forensic_assistant.database.db import connect


def packet():
    p={'kind':'case_assessment','id':'a'*32,'status':'COMPLETE_WITH_LIMITATIONS',
       'plan':{'case':{'path':r'C:\Synthetic\Example\case.db'},'revision':2,'objectives':[],
       'reported_times':[{'kind':'date','value':'September 30, 2026','status':'provided','statement':'Long source\\nunchanged'},
                         {'kind':'ambiguous_time','value':'09:30','status':'approximate','statement':'Long source\\nunchanged'}],
       'start':'2026-09-30T00:00:00Z','end':'2026-09-30T23:59:59Z',
       'editorial_summary':'Reported arrival and execution questions remain unverified.',
       'leads':[{'id':'L1','occurrences':[{'original':'sample.ps1'}]},{'id':'L2','occurrences':[{'original':'example.org'}]}]},
       'records':{},'timeline':[],'interpretations':[],'rows':[],'warnings':[], 'integrity_verified':True,
       'metrics':{'queries':112,'candidates':99020,'bytes':12345,'elapsed_seconds':20.8}}
    for family in ('browser','mft','prefetch','evtx'):
        eid=family.upper()+':'+('b'*64)+':synthetic'
        fields=[{'field':'objects.referenced_file' if family=='prefetch' else 'objects.file_path',
                 'value':r'C:\Synthetic\sample.ps1','truncated':False}]
        p['records'][eid]={'artifact':family,'lead_ids':['L1','L2'] if family=='browser' else ['L1'],
            'matched_fields_by_lead':{'L1':fields},'source_context':{},
            'match':{'source_file':r'C:\Private\original.bin','matched_fields':fields,'timestamps':[],
                     'limitations':[],'timestamps_truncated':False,'source_file_truncated':False}}
        specs={'browser':[('Browser.DownloadStart','Browser-recorded DownloadStart'),('Browser.DownloadEnd','Browser-recorded DownloadEnd')],
               'mft':[('si:Created','Filesystem metadata SI Created timestamp'),('fn:Created','Filesystem metadata FN Created timestamp'),
                      ('si:Modified','Filesystem metadata SI Modified timestamp')],
               'prefetch':[('run:0','Recorded execution timestamp'),('run:1','Recorded execution timestamp')],
               'evtx':[('SystemTime','Event timestamp')]}[family]
        for slot,meaning in specs:
            t={'evidence_id':eid,'artifact':family,'slot':slot,'meaning':meaning,'timestamp_utc':'2026-09-30T14:05:44.000000000Z'}
            p['timeline'].append(t);p['records'][eid]['match']['timestamps'].append(t)
        p['rows'].append({'lead_id':'L1','artifact':family,'status':'incomplete' if family=='evtx' else 'match',
                         'pages':25,'candidates':25000,'evidence_ids':[eid],'cursor':'private-encoded-cursor','limitations':[]})
    p['interpretations']=[{'evidence_id':next(e for e in p['records'] if e.startswith('EVTX:')),
                          'text':'Defender recorded a blocking action; successful execution is not established.'}]
    return p


def test_default_and_details_same_data():
    p=packet();before=copy.deepcopy(p);human=a.render(p);technical=a.render(p,details=True)
    assert p==before
    assert '4 distinct records across 4 artifact families' in human
    assert 'private-encoded-cursor' not in human and 'C:\\Private' not in human
    for eid in p['records']:assert eid not in human and eid in technical
    assert human.count('Briefing context')==1
    assert '[E1]' in human and 'example.org' in human
    assert 'source_context' not in human and 'source_context' in technical
    assert 'private-encoded-cursor' in technical
    assert 'blocking action' in human and 'does not establish execution' in human
    assert 'Search coverage: incomplete — evtx' in human
    assert 'Discovery pass: completed' in human and 'Forensic investigation: preliminary and incomplete' in human


def test_chronology_condenses_without_changing_types():
    p=packet();citations={e:str(i) for i,e in enumerate(p['records'])};rows,omitted=d.chronology(p,citations)
    assert len(rows)==4 and omitted==1
    mft=next(r for r in rows if 'MFT' in r)
    assert ' SI' in mft and ' FN' in mft and 'Modified' not in mft
    assert any('DownloadStart' in r and 'DownloadEnd' in r for r in rows)
    assert any('not referenced-file execution' in r for r in rows)
    assert all('UTC' in r for r in rows)
    assert len(p['timeline'])==8


def test_unknown_time_editorial_objectives_and_ambiguity():
    p=packet();p['briefing_stale']=True
    r=next(iter(p['records'].values()));r['source_context']={'hostname':None,'source_ids':['one','two'],'conflicts':['volume ambiguity']}
    text=a.render(p)
    assert 'Approximate time: 09:30' in text and 'Timezone: Unknown' in text
    assert '09:30 UTC' not in text and 'Long source' not in text and '\\n' not in text
    assert 'Structured objectives unavailable' in text and 'Accepted editorial summary' in text
    assert 'not structured objective fields' in text
    assert 'attribution is ambiguous' in text and 'older briefing revision' in text


def test_historical_unknown_labels_and_new_known_labels():
    p=packet();old=a.render(p)
    assert 'Explorer' not in old and 'Edge' not in old
    assert 'Browser recorded a download' in old
    for record in p['records'].values():
        if record['artifact']=='prefetch':record['presentation']={'process_name':'EXPLORER.EXE'}
        if record['artifact']=='browser':record['presentation']={'artifact_type':'browser_download','browser_product':'Edge'}
    text=a.render(p)
    assert 'EXPLORER.EXE Prefetch references' in text and 'Edge recorded a download' in text


def test_missing_data_failure_no_false_absence_or_control_sequences():
    p=packet();p['records']={};p['timeline']=[];p['interpretations']=[]
    p['rows'][0].update(status='failed',limitations=['Lookup failed\x1b[31m'])
    text=a.render(p)
    assert 'does not establish absence' in text and 'No timestamps retained' in text
    assert '\x1b' not in text and 'failed' in text


def test_progress_throttles_but_reports_failure_and_details():
    p=packet();s=io.StringIO();clock=[0.0];progress=d.Progress(s,clock=lambda:clock[0])
    for n in range(100):
        clock[0]=n*.1;progress.assessment_update('evtx Searching',p)
    progress.assessment_update('evtx failed — problem',p)
    assert len(s.getvalue().splitlines())<=7
    assert 'lookup failed' in s.getvalue() and '4 distinct matches' in s.getvalue()
    s=io.StringIO();progress=d.Progress(s,details=True)
    for _ in range(100):progress.assessment_update('evtx Searching',p)
    assert len(s.getvalue().splitlines())==100


def test_saved_show_same_render_no_queries(case):
    with closing(connect(case)) as db:
        result=cli.run(arguments(case,'assess','--start','2026-09-30T00:00:00Z','--end','2026-09-30T23:59:59Z',answers=['','y']),worker_factory=factory(db))
    before=AssessmentStore(case).load(result['id'])
    shown=cli.run(arguments(case,'show',result['id']),worker_factory=lambda _:pytest.fail('query'))
    assert a.render(result)==a.render(shown)
    assert before==AssessmentStore(case).load(result['id'])
    assert 'presentation' in next(iter(result['records'].values()))
    assert cli.run(arguments(case,'list'))['assessments'][0]['id']==result['id']


def test_render_measurement():
    p=packet();tracemalloc.start();start=time.perf_counter()
    text=a.render(p);elapsed=time.perf_counter()-start;_,peak=tracemalloc.get_traced_memory();tracemalloc.stop()
    print(f'Render: {elapsed:.6f}s; output={len(text.encode())} bytes; Python heap peak={peak} bytes')


def test_historical_editorial_context_exact_revision_and_json(case):
    from forensic_assistant.briefing_store import Store, content, FIELDS
    from forensic_assistant import briefing_canonical as canonical
    store=Store(case);old=store.load()['revisions'][-1]
    document=copy.deepcopy(old['content']['canonical']['document'])
    document['categories']['objectives']=[]
    document['summary'].update(status='accepted',text='Review reported arrival and execution.',statement='Review reported arrival and execution.')
    revision=store.save(content(dict.fromkeys(FIELDS,''),'',canonical=canonical.envelope(document)),old['digest'])['revisions'][-1]
    with closing(connect(case)) as db:
        result=cli.run(arguments(case,'assess','--start','2026-09-30T00:00:00Z','--end','2026-09-30T23:59:59Z',answers=['','y']),worker_factory=factory(db))
    assert result['plan']['editorial_summary']==document['summary']['text']
    result['plan'].pop('editorial_summary')  # Historical presentation shape.
    result['authorization']['plan_digest']=a.digest(result['plan'])
    AssessmentStore(case).save_assessment(result)
    before=AssessmentStore(case).load(result['id'])
    document['summary']['text']='Different current editorial context.'
    store.save(content(dict.fromkeys(FIELDS,''),'',canonical=canonical.envelope(document)),revision['digest'])
    shown=cli.run(arguments(case,'show',result['id']),worker_factory=lambda _:pytest.fail('query'))
    text=a.render(shown)
    assert 'Review reported arrival and execution.' in text and 'Different current editorial' not in text
    assert shown['briefing_stale'] and 'Structured objectives unavailable' in text
    machine=cli.run(arguments(case,'show',result['id'],'--json'))
    assert 'briefing_report_context' not in machine
    assert AssessmentStore(case).load(result['id'])==before


def test_tty_progress_and_running_checkpoint():
    class Terminal(io.StringIO):
        def isatty(self):return True
    p=packet();s=Terminal();clock=[0.0];progress=d.Progress(s,clock=lambda:clock[0])
    progress.assessment_update('evtx Searching',p);clock[0]=3
    progress.assessment_update('evtx Searching',p)
    assert '\n' not in s.getvalue() and s.getvalue().count('\r')==2
    progress.finish();assert s.getvalue().endswith('\n')
    p['status']='RUNNING'
    assert 'current process activity are unconfirmed' in a.render(p)
