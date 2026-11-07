"""Synthetic initial assessment authorization, scheduling, persistence and isolation."""
import copy
import json
import time
import tracemalloc
from contextlib import closing
import pytest
from forensic_assistant import assessment as a, assessment_cli as cli, briefing_canonical as canonical
from forensic_assistant.assessment_store import AssessmentStore
from forensic_assistant.briefing_store import Store,content,FIELDS
from forensic_assistant.cli import build_parser
from forensic_assistant.database.db import connect
from forensic_assistant.retrieval import evtx_content
from test_briefing_cross_artifact import artifact,Worker
from test_evtx_content import add
from test_briefing import START,END


def accepted(case, values=('baje.ps1',)):
    document=canonical.empty()
    for value in values:
        document['categories']['files'].append(dict(status='provided',kind='filename',value=value,statement=value,note='',polarity='reported'))
    document['categories']['when']=[dict(status='approximate',kind='ambiguous_time',value='09:30',statement='about 09:30, timezone unknown',note='',polarity='reported')]
    document['categories']['objectives']=[dict(status='provided',kind='objective',value='Determine execution.',statement='Determine execution.',note='',polarity='reported')]
    store=Store(case);old=store.load()
    return store.save(content(dict.fromkeys(FIELDS,''),'',canonical=canonical.envelope(document)),old['revisions'][-1]['digest'] if old else None)['revisions'][-1]


@pytest.fixture
def case(tmp_path):
    path=tmp_path/'case.db'
    with closing(connect(path)) as db:
        add(db)
        for family in ('mft','prefetch','registry','browser'):artifact(db,family)
    accepted(path)
    return path


class ViewWorker(Worker):
    def __init__(self,db):super().__init__(db);self.view={'view_id':'synthetic-one'}
    def call(self,name,args=None,**kwargs):
        result=super().call(name,args,**kwargs)
        result['evidence_state']=dict(self.view)
        return result


def arguments(case,*words,answers=()):
    args=build_parser().parse_args(['--db',str(case),'briefing',*words])
    iterator=iter(answers);args._confirm=lambda prompt:next(iterator)
    return args


def factory(db):return lambda config:ViewWorker(db)


def test_plan_accepted_only_exclusions_time(case):
    revision=Store(case).load()['revisions'][-1]
    revision=copy.deepcopy(revision)
    item=revision['content']['canonical']['document']['categories']['files'][0]
    item['polarity']='negated'
    revision['content']['canonical']=canonical.envelope(revision['content']['canonical']['document'])
    p=a.plan(revision,AssessmentStore(case).identity,list(a.briefing.ARTIFACTS),START,END)
    assert not p['leads'] and any(r['reason'].startswith('Missing') for r in p['excluded'])
    assert p['reported_times'][0]['statement']=='about 09:30, timezone unknown'
    with pytest.raises(ValueError):a.plan(revision,{},[], '2026-09-30T09:30:00',END)
    with pytest.raises(ValueError):a.plan(revision,{},[],START,'2026-10-02T00:00:00Z')


def test_reject_and_exclude_no_search_or_persistence(case):
    before=case.read_bytes()
    with closing(connect(case)) as db:
        workers=[]
        def make(config):
            worker=ViewWorker(db);workers.append(worker);return worker
        result=cli.run(arguments(case,'--assess','--start',START,'--end',END,answers=['','n']),worker_factory=make)
        assert 'cancelled' in result['message']
        assert not AssessmentStore(case).root.exists()
        assert all('briefing_search' not in w.calls for w in workers)
    assert case.read_bytes()==before


def test_assessment_persists_evidence_timeline_no_model(case,monkeypatch):
    from forensic_assistant.ai.backend import ModelBackend
    monkeypatch.setattr(ModelBackend,'complete',lambda *a,**k:pytest.fail('model'))
    before=case.read_bytes()
    with closing(connect(case)) as db:
        p=cli.run(arguments(case,'--assess','--start',START,'--end',END,answers=['','yes']),worker_factory=factory(db))
    assert p['status']=='COMPLETE' and p['integrity_verified']
    assert len(p['records'])==5 and p['metrics']['queries']==5
    assert all('slot' in r and 'meaning' in r and 'evidence_id' in r for r in p['timeline'])
    assert p['authorization']['plan_digest']==a.digest(p['plan'])
    saved=AssessmentStore(case).load(p['id']);assert saved==p
    text=a.render(saved)
    assert 'not prove file identity' in text or 'not file identity' in text or 'Basename candidate' in text
    assert 'execution' in text and 'not confirm the whole narrative' in text
    assert case.read_bytes()==before
    shown=cli.run(arguments(case,'--assessment-show'),worker_factory=lambda c:pytest.fail('review executes'))
    assert shown['id']==p['id'] and not shown['briefing_stale']
    assert len(cli.run(arguments(case,'--assessment-history'))['assessments'])==1


def test_automatic_continuation_and_dedup(case,monkeypatch):
    monkeypatch.setattr(evtx_content,'CANDIDATES',1)
    with closing(connect(case)) as db:
        add(db,1);add(db,2)
        p=cli.run(arguments(case,'--assess','--start',START,'--end',END,answers=['','y']),worker_factory=factory(db))
    evtx=next(r for r in p['rows'] if r['artifact']=='evtx')
    assert evtx['pages']==3 and len(evtx['evidence_ids'])==3 and evtx['status']=='match'
    assert len(p['records'])==7
    assert evtx['candidates']==3


def test_budget_fairness_resume_separate_view(case,monkeypatch):
    monkeypatch.setitem(a.POLICY,'queries',2)
    with closing(connect(case)) as db:
        first=cli.run(arguments(case,'--assess','--start',START,'--end',END,answers=['','y']),worker_factory=factory(db))
        assert first['status']=='COMPLETE_WITH_LIMITATIONS'
        assert [r['artifact'] for r in first['rows'] if r['pages']]==['mft','prefetch']
        second=cli.run(arguments(case,'--assessment-resume',answers=['','y']),worker_factory=factory(db))
    assert second['parent']==first['id'] and second['id']!=first['id']
    assert second['metrics']['queries']==2
    assert any('not merged' in n for n in second['warnings'])
    assert len(AssessmentStore(case).history())==2
    accepted(case,('other.exe',))
    assert cli.run(arguments(case,'--assessment-show',first['id']))['briefing_stale']
    with pytest.raises(ValueError,match='Briefing changed'):
        cli.run(arguments(case,'--assessment-resume',first['id'],answers=[]))


def test_interruption_and_failed_view_saved(case):
    class Cancel(ViewWorker):
        def call(self,name,args=None,**kwargs):
            if name=='briefing_search':raise KeyboardInterrupt
            return super().call(name,args,**kwargs)
    with closing(connect(case)) as db:
        p=cli.run(arguments(case,'--assess','--start',START,'--end',END,answers=['','y']),worker_factory=lambda _:Cancel(db))
    assert p['status']=='CANCELLED' and any(r['status']=='incomplete' for r in p['rows'])
    assert AssessmentStore(case).load(p['id'])['status']=='CANCELLED'


def test_case_identity_and_integrity_envelope(case):
    with closing(connect(case)) as db:
        p=cli.run(arguments(case,'--assess','--start',START,'--end',END,answers=['','y']),worker_factory=factory(db))
    store=AssessmentStore(case);path=store.root/(p['id']+'.json')
    raw=json.loads(path.read_text());raw['assessment']['case']['inode']=-1
    raw['digest']=a.digest(raw['assessment']);path.write_text(json.dumps(raw))
    with pytest.raises(ValueError,match='identity'):store.load(p['id'])


def test_real_worker_synthetic_only(case):
    before=case.read_bytes()
    result=cli.run(arguments(case,'--assess','--start',START,'--end',END,answers=['','y']))
    assert result['status']=='COMPLETE' and result['integrity_verified'] and len(result['records'])==5
    assert case.read_bytes()==before


def test_briefing_change_during_approval(case):
    args=arguments(case,'--assess','--start',START,'--end',END)
    def read(prompt):
        if prompt.startswith('Exclude'):return ''
        accepted(case,('new.ps1',));return 'y'
    args._confirm=read
    with closing(connect(case)) as db:
        with pytest.raises(ValueError,match='changed during approval'):
            cli.run(args,worker_factory=factory(db))
    assert not AssessmentStore(case).root.exists()


def test_exclude_one_lead_and_dedup_between_terms(case):
    revision=accepted(case,('baje.ps1','other.exe'))
    with closing(connect(case)) as db:
        p=a.plan(revision,AssessmentStore(case).identity,list(a.briefing.ARTIFACTS),START,END)
        excluded=p['leads'][1]['id']
        result=cli.run(arguments(case,'--assess','--start',START,'--end',END,answers=[excluded,'y']),worker_factory=factory(db))
        assert len(result['plan']['leads'])==1
        assert all(r['lead_id']!=excluded for r in result['rows'])
    state=Store(case).load();v=copy.deepcopy(state['revisions'][-1]['content'])
    doc=v['canonical']['document'];doc['categories']['activity']=[dict(status='provided',kind='activity',value='powershell.exe',statement='powershell.exe',note='',polarity='reported')]
    v['canonical']=canonical.envelope(doc);Store(case).save(v,state['revisions'][-1]['digest'])
    with closing(connect(case)) as db:
        result=cli.run(arguments(case,'--assess','--start',START,'--end',END,answers=['','y']),worker_factory=factory(db))
    evtx=[r for r in result['records'].values() if r['artifact']=='evtx']
    assert len(evtx)==1 and len(evtx[0]['lead_ids'])==2 and len(evtx[0]['matched_fields_by_lead'])==2


def test_failed_search_and_changed_readview(case):
    from forensic_assistant.investigation_ai.runner import WorkerError
    class Failed(ViewWorker):
        def call(self,name,args=None,**kwargs):
            if name=='briefing_search' and args['artifact']=='mft':raise WorkerError('Synthetic failure')
            return super().call(name,args,**kwargs)
    with closing(connect(case)) as db:
        p=cli.run(arguments(case,'--assess','--start',START,'--end',END,answers=['','y']),worker_factory=lambda _:Failed(db))
        assert p['status']=='COMPLETE_WITH_LIMITATIONS' and len(p['records'])==4
        class Changed(ViewWorker):
            def call(self,name,args=None,**kwargs):
                if name=='briefing_search':self.view={'view_id':'different'}
                return super().call(name,args,**kwargs)
        p=cli.run(arguments(case,'--assess','--start',START,'--end',END,answers=['','y']),worker_factory=lambda _:Changed(db))
        assert p['status']=='FAILED' and not p['records'] and not p['integrity_verified']


@pytest.mark.parametrize('resource,value',[('bytes',1),('records',1),('candidates',1),('queries',1),('seconds',4)])
def test_aggregate_resource_bounds(case,monkeypatch,resource,value):
    monkeypatch.setitem(a.POLICY,resource,value)
    with closing(connect(case)) as db:
        p=cli.run(arguments(case,'--assess','--start',START,'--end',END,answers=['','y']),worker_factory=factory(db))
    assert p['status']=='COMPLETE_WITH_LIMITATIONS'
    assert len(p['records'])<=a.POLICY['records'] and p['metrics']['candidates']<=a.POLICY['candidates'] and p['metrics']['bytes']<=a.POLICY['bytes']


def test_payload_persistence_atomic_failure_preserves_previous(case,monkeypatch):
    with closing(connect(case)) as db:
        p=cli.run(arguments(case,'--assess','--start',START,'--end',END,answers=['','y']),worker_factory=factory(db))
    store=AssessmentStore(case);path=store.root/(p['id']+'.json');before=path.read_bytes()
    from forensic_assistant import briefing_store
    monkeypatch.setattr(briefing_store.os,'replace',lambda *a:(_ for _ in ()).throw(OSError('synthetic failure')))
    with pytest.raises(OSError):store.save_assessment(p)
    assert path.read_bytes()==before


def test_assessment_measurement(case,monkeypatch):
    monkeypatch.setattr(evtx_content,'CANDIDATES',10)
    with closing(connect(case)) as db:
        for n in range(1,101):add(db,n,data=[('Path','other.exe')])
        store=AssessmentStore(case);revision=Store(case).load()['revisions'][-1]
        p=a.plan(revision,store.identity,list(a.briefing.ARTIFACTS),START,END)
        tracemalloc.start();at=time.perf_counter()
        result=a.execute(p,store,worker_factory=factory(db))
        elapsed=time.perf_counter()-at;_,peak=tracemalloc.get_traced_memory();tracemalloc.stop()
    assert result['status']=='COMPLETE' and result['metrics']['queries']==15
    assert result['metrics']['candidates']==117
    output_bytes=len(a.render(result).encode())
    print(f'Assessment benchmark: {elapsed:.4f}s; queries={result["metrics"]["queries"]}; candidates={result["metrics"]["candidates"]}; output={output_bytes} bytes; Python heap peak={peak} bytes; saved={ (store.root/(result["id"]+".json")).stat().st_size } bytes')


def test_repeated_cursor_stops_and_missing_families_reported(tmp_path):
    path=tmp_path/'empty.db'
    with closing(connect(path)) as db:add(db)
    accepted(path)
    class Repeat(ViewWorker):
        saved=None
        def call(self,name,args=None,**kwargs):
            if name!='briefing_search':return super().call(name,args,**kwargs)
            if self.saved is None:self.saved=super().call(name,args,**kwargs)
            result=copy.deepcopy(self.saved)
            result['result']['content_search'].update(complete=False,next_cursor='same-cursor')
            return result
    with closing(connect(path)) as db:
        p=cli.run(arguments(path,'--assess','--start',START,'--end',END,answers=['','y']),worker_factory=lambda _:Repeat(db))
    assert p['metrics']['queries']==2 and len(p['records'])==1
    assert p['rows'][0]['status']=='incomplete'
    assert sum(r['status']=='unavailable' for r in p['rows'])==4
    assert any('Repeated' in s for s in p['rows'][0]['limitations'])


def test_raw_narrative_and_summary_are_not_assessment_leads(case):
    s=Store(case);state=s.load();v=copy.deepcopy(state['revisions'][-1]['content'])
    v['narrative']='invented.exe'
    v['canonical']['original_provenance']['excluded_suggestions']=[{'literal':'excluded.exe'}]
    doc=v['canonical']['document'];doc['summary']={'text':'phantom.exe','statement':'phantom.exe','status':'accepted'}
    v['canonical']=canonical.envelope(doc,v['canonical']['original_provenance'])
    revision=s.save(v,state['revisions'][-1]['digest'])['revisions'][-1]
    p=a.plan(revision,AssessmentStore(case).identity,list(a.briefing.ARTIFACTS),START,END)
    assert [r['occurrences'][0]['original'] for r in p['leads']]==['baje.ps1']


def test_no_accepted_briefing_no_inventory(tmp_path):
    path=tmp_path/'case.db';connect(path).close()
    with pytest.raises(ValueError,match='Accept a structured'):
        cli.run(arguments(path,'--assess'),worker_factory=lambda _:pytest.fail('worker'))


def test_empty_case_can_save_approved_coverage_assessment(tmp_path):
    path=tmp_path/'empty.db';connect(path).close();accepted(path)
    with closing(connect(path)) as db:
        result=cli.run(arguments(path,'--assess','--start',START,'--end',END,answers=['','y']),worker_factory=factory(db))
    assert result['status']=='COMPLETE_WITH_LIMITATIONS' and result['metrics']['queries']==0
    assert not result['records'] and all(r['status']=='unavailable' for r in result['rows'])
    assert AssessmentStore(path).load(result['id'])['id']==result['id']
