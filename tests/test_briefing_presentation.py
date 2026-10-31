"""Presentation and provider-consent regression tests; synthetic inputs only."""
import copy
import json
import pytest
from forensic_assistant import briefing as b, briefing_cli
from forensic_assistant.ai import settings
from forensic_assistant.ai.backend import ModelBackend
from forensic_assistant.cli import build_parser, main
from test_briefing import Fake, item, MemoryWorker, START, END
from test_evtx_content import add
from forensic_assistant.database.db import connect
from contextlib import closing


@pytest.mark.parametrize('provider,ack,legacy,allowed', [
    ('openai', True, False, True), ('openai', False, False, False),
    ('openai', False, True, True), ('local', False, False, True)])
def test_consent(provider, ack, legacy, allowed):
    f=Fake({'items':[]}); f.provider_name=provider
    f.config={'provider':provider,'cloud_acknowledged':ack}
    p=b.extract('sample.ps1')
    if allowed:
        b.interpret(p,f,allow_cloud=legacy)
        assert len(f.calls)==1
    else:
        with pytest.raises(ValueError,match='disclosure'):b.interpret(p,f)
        assert not f.calls


def test_backend_rejects_unacknowledged_and_mismatched_provider(monkeypatch):
    monkeypatch.setenv('OPENAI_API_KEY','fake-key-not-authorization')
    with pytest.raises(ValueError,match='acknowledged'):
        ModelBackend(config={**settings.defaults(),'provider':'openai','model':'example'})
    f=Fake({'items':[]}); f.provider_name='openai'
    f.config={'provider':'anthropic','cloud_acknowledged':True}
    with pytest.raises(ValueError):b.interpret(b.extract('sample.ps1'),f)
    assert not f.calls


@pytest.mark.parametrize('status', ['not_requested','success','partial','failed','skipped'])
def test_status_and_views_preserve_packet(status):
    p=b.extract('Reported sample.ps1 activity.\x1b[31m')
    good=item('Reported sample.ps1 activity.\x1b[31m')
    b.interpret(p,Fake({'items':[good, {**good,'source_ids':['S-forged']}]}))
    p['ai_status']=status
    if status in ('not_requested','failed','skipped'):p['ai_items']=[]
    before=copy.deepcopy(p)
    human=briefing_cli.render(p); technical=briefing_cli.render(p,details=True)
    assert p==before and '\x1b' not in human and '\x1b' not in technical
    assert 'S-forged' not in human and 'unknown_source_id' not in human
    assert 'original:0..' not in human
    assert p['leads'][0]['id'] in technical
    assert 'Technical packet' in technical
    assert 'No forensic evidence searched.' in human
    if status=='partial':
        assert '1 interpretations accepted; 1 rejected' in human
        assert 'AI interpretation failed:' not in human
    if status=='failed':assert 'no interpretations accepted' in human


@pytest.mark.parametrize('count,incomplete', [(0,False),(1,False),(2,True)])
def test_discovery_readable_original_and_derived(count,incomplete):
    with closing(connect(':memory:')) as db:
        add(db); p=b.extract('baje.ps1')
        identity=p['leads'][0]['id']; worker=MemoryWorker(db)
        before=db.total_changes
        b.discover(p,'synthetic.db',[identity],'evtx',START,END,worker_factory=lambda config:worker)
        assert db.total_changes==before
    result=p['discovery']['queries'][0]['result']
    original=result['records'][0]
    result['records']=[copy.deepcopy(original) for _ in range(count)]
    result['content_search']={'complete':not incomplete}
    snapshot=copy.deepcopy(p)
    output=briefing_cli.render(p)
    assert p==snapshot and str(count)+' evidence records returned' in output
    assert START in output and END in output and 'baje.ps1' in output
    assert original['id'] not in output
    assert 'Investigation has not yet been performed' in output
    if count:
        assert 'Original EventData:' in output and 'Deterministic interpretation:' in output
    else:assert 'does not establish absence' in output
    if incomplete:assert 'Search coverage is incomplete' in output
    assert original['id'] in briefing_cli.render(snapshot,details=True) if count else True


def test_cli_json_unchanged_and_exact_approval_mapping(capsys, monkeypatch):
    expected=b.extract('sample.ps1')
    monkeypatch.setattr(briefing_cli, 'run', lambda args: expected)
    assert main(['briefing','--text','sample.ps1','--json','--details'])==0
    p=json.loads(capsys.readouterr().out)
    assert p==expected
    assert main(['briefing','--text','sample.ps1'])==0
    output=capsys.readouterr().out
    assert '--approve '+p['leads'][0]['id'] in output
    with pytest.raises(ValueError,match='Unknown approved'):
        b.discover(p,'unused.db',['1'],'evtx',START,END)
    assert build_parser().parse_args(['briefing','--text','x','--details']).details
