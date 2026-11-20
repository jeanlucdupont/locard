"""Format-1 compatibility, synthetic files only; no providers or real cases."""
import copy
import json
from contextlib import closing
import pytest
from forensic_assistant import briefing_canonical as canonical, briefing_semantics as semantics
from forensic_assistant import briefing_store as storage, case_management, activity
from forensic_assistant.database.db import connect
from forensic_assistant.database import sources
from forensic_assistant.assessment_store import AssessmentStore
from forensic_assistant import assessment, assessment_cli
from test_assessment import arguments, factory
from test_briefing_canonical import entry
from test_interactive_shell import Input
from forensic_assistant.interactive.shell import Shell
from forensic_assistant.interactive.state import State


@pytest.fixture
def legacy(tmp_path,monkeypatch):
    monkeypatch.setenv('LOCALAPPDATA',str(tmp_path/'app'))
    monkeypatch.setenv('USERPROFILE',str(tmp_path/'user'))
    case=tmp_path/'case.db'
    with closing(connect(case)) as db:
        with db:sid=sources.create(db,hostname='lab-node-7')
    store=storage.Store(case)
    original=storage.content(dict.fromkeys(storage.FIELDS,''),'Investigate the computer on the reported day.')
    first=store.save(original,None)['revisions'][0]
    doc=canonical.empty();doc['categories']['systems']=[entry('on','hostname')]
    doc['summary']={'text':'Reported activity remains unverified.','status':'accepted','statement':original['narrative']}
    accepted=copy.deepcopy(original);accepted['canonical']=canonical.envelope(doc)
    state=store.save(accepted,first['digest'])
    session=activity.Session(case);session.start();session.end()
    return store,state,sid


def test_reproduce_6160_validator_regression(legacy,monkeypatch):
    store,state,_=legacy
    before=store.path.read_bytes()
    # 6.160 check() called the current technical policy without a format profile.
    original=semantics.technical
    monkeypatch.setattr(canonical,'technical',lambda kind,value,**kwargs:original(kind,value))
    with pytest.raises(ValueError,match=r'BRIEFING_MALFORMED: canonical.document.categories.systems\[0\].value: invalid_technical_value'):
        store.load()
    assert store.path.read_bytes()==before


def test_historical_read_preserves_all_bytes_and_decisions(legacy):
    store,state,_=legacy
    before={p:p.read_bytes() for p in (store.path,store.case,activity.sidecar(store.case))}
    assert case_management.validate_identity(store.case)==store.case
    assert store.load()==state
    assert AssessmentStore(store.case).history()==[]
    assert all(p.read_bytes()==raw for p,raw in before.items())
    with pytest.raises(ValueError):semantics.technical('hostname','on')
    assert canonical.check_envelope(state['revisions'][-1]['content']['canonical'])


@pytest.mark.parametrize('value',['on','during','windows','http://on'])
def test_format1_value_policy_not_search_authority(value):
    kind='url' if '://' in value else 'hostname'
    doc=canonical.empty();doc['categories']['systems']=[entry(value,kind)]
    assert canonical.check(doc)==doc
    with pytest.raises(ValueError):semantics.technical(kind,value)


@pytest.mark.parametrize('mode',['unknown_field','invalid_hostname','invalid_type','digest','unsupported'])
def test_malformed_preserved_and_diagnostics_sanitized(legacy,mode):
    store,state,_=legacy;state=copy.deepcopy(state)
    c=state['revisions'][-1]['content'];item=c['canonical']['document']['categories']['systems'][0]
    if mode=='unknown_field':item['secret-narrative']='private text'
    elif mode=='invalid_hostname':item['value']=item['statement']='private invalid host!'
    elif mode=='invalid_type':item['value']=42
    elif mode=='digest':c['narrative']='changed privately'
    else:state['format']=99
    if mode!='digest':state['revisions'][-1]['digest']=storage.digest(c)
    store.path.write_text(json.dumps(state),encoding='utf-8')
    before=store.path.read_bytes()
    with pytest.raises(ValueError) as caught:store.load()
    message=str(caught.value)
    assert 'BRIEFING_' in message
    assert not any(secret in message for secret in ('private','secret-narrative','changed privately'))
    if mode in ('invalid_hostname','invalid_type'):assert 'systems[0].value' in message
    assert store.path.read_bytes()==before


@pytest.mark.parametrize('remembered',[True,False])
def test_remembered_and_explicit_open(legacy,remembered,capsys):
    store,state,_=legacy;before=store.path.read_bytes();evidence=store.case.read_bytes()
    audit=activity.sidecar(store.case).read_bytes()
    ui=State(None)
    if remembered:ui.remember(store.case)
    shell=Shell(ui,Input(''))
    try:
        assert shell.startup() if remembered else shell.choose(str(store.case))
        assert shell.active==store.case
    finally:
        if shell.audit:shell.audit.end()
    assert 'BRIEFING_MALFORMED' not in capsys.readouterr().out
    assert store.path.read_bytes()==before and store.case.read_bytes()==evidence
    # Opening creates a new audited session, never rewrites historical entries.
    assert activity.sidecar(store.case).read_bytes().startswith(audit)


def test_legacy_assertion_excluded_but_time_plan_executes(legacy):
    store,state,sid=legacy;before=store.path.read_bytes();evidence=store.case.read_bytes()
    revision=state['revisions'][-1]
    plan=assessment.plan(revision,AssessmentStore(store.case).identity,[], '2020-01-01T00:00:00Z','2020-01-02T00:00:00Z')
    assert not plan['leads']
    assert any(row['value']=='on' for row in plan['excluded'])
    with closing(connect(store.case)) as db:
        result=assessment_cli.run(arguments(store.case,'assess','--source',sid,'--start','2020-01-01T00:00:00Z','--end','2020-01-02T00:00:00Z',answers=['','yes']),worker_factory=factory(db))
    assert result['plan']['source_id']==sid and result['integrity_verified']
    assert all(row['status']=='unavailable' for row in result['rows'])
    assert store.path.read_bytes()==before and store.case.read_bytes()==evidence
    assert store.load()==state
