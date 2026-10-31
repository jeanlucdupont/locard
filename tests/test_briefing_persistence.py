"""Synthetic case briefing persistence; no real evidence, editors or providers."""
import copy
import json
from pathlib import Path
import pytest
from forensic_assistant import briefing_cli as cli, briefing_store as storage, briefing_workflow as workflow
from forensic_assistant import briefing
from forensic_assistant.cli import build_parser
from forensic_assistant.database.db import connect


@pytest.fixture
def store(tmp_path):
    case=tmp_path/'case.db'
    db=connect(case);db.close()
    return storage.Store(case)


def value(text='sample.ps1'):
    return storage.content(dict.fromkeys(storage.FIELDS,''),text)


def args(store,*words):
    return build_parser().parse_args(['--db',str(store.case),'briefing',*words])


def test_revisions_atomic_unchanged_and_case_bytes(store,monkeypatch):
    original=store.case.read_bytes()
    one=store.save(value(),None)
    assert store.save(value(),one['revisions'][-1]['digest'])==one
    two=store.save(value('second.ps1'),one['revisions'][-1]['digest'])
    assert len(two['revisions'])==2 and two['revisions'][0]==one['revisions'][0]
    before=store.path.read_bytes()
    monkeypatch.setattr(storage.os,'replace',lambda *a:(_ for _ in ()).throw(OSError('simulated')))
    with pytest.raises(OSError):store.save(value('third.ps1'),two['revisions'][-1]['digest'])
    assert store.path.read_bytes()==before and store.case.read_bytes()==original
    assert not list(store.root.glob('.save-*')) and not (store.root/'write.lock').exists()


def test_conflicting_update_and_case_mismatch(store):
    state=store.save(value(),None)
    with pytest.raises(ValueError,match='changed'):store.save(value('other'),None)
    raw=json.loads(store.path.read_text());raw['case']['inode']+=1
    store.path.write_text(json.dumps(raw))
    with pytest.raises(ValueError,match='identity'):store.load()


@pytest.mark.parametrize('raw',['{}','not JSON','{"format":1,"format":1}', '[]'])
def test_corrupt_preserved(store,raw):
    store.save(value(),None);store.path.write_text(raw)
    with pytest.raises(ValueError):store.load()
    assert store.path.read_text()==raw


def test_missing_and_lock(store):
    assert store.load() is None
    store.save(value(),None)
    (store.root/'write.lock').write_text('')
    with pytest.raises(ValueError,match='busy'):store.save(value('x'),store.load()['revisions'][-1]['digest'])
    store.path.unlink()
    with pytest.raises(ValueError,match='incomplete'):store.load()


@pytest.mark.parametrize('text',['\ufeffHello\r\nsample.ps1\nUnicode café','', 'unknown'])
def test_text_roundtrip_sources(store,text):
    v=value(text);v['answers']['people']='Unknown; not a negative assertion'
    v['answers']['indicators']='sample.ps1'
    state=store.save(v,None);revision=store.load()['revisions'][-1]
    assert revision['content']==v
    p=briefing.extract_inputs(storage.sources(revision))
    for unit in p['source_units']:
        assert p['inputs'][unit['source']][unit['start']:unit['end']]==unit['text']
    assert any(u['source']=='field:indicators' for u in p['source_units'])
    assert len({u['id'] for u in p['source_units']})==len(p['source_units'])


def test_wizard_skip_clear_retain_cancel(store):
    v=value('narrative retained');v['answers']['people']='Person';v['answers']['systems']='System'
    answers=iter(['','','','/clear','','','','','','yes'])
    result=workflow.wizard(v,lambda prompt:next(answers))
    assert result['answers']['people']=='Person' and result['answers']['systems']=='' and result['narrative']==v['narrative']
    with pytest.raises(KeyboardInterrupt):workflow.wizard(v,lambda prompt:'cancel')
    assert not store.root.exists()
    a=args(store,'--wizard');sequence=iter(['']*9+['yes']);a._confirm=lambda p:next(sequence)
    assert cli.run(a)['revision']['revision']==1


def test_show_no_analysis_and_staleness(store,monkeypatch):
    from forensic_assistant.ai.backend import ModelBackend
    monkeypatch.setattr(ModelBackend,'complete',lambda *a:pytest.fail('model called'))
    assert 'No saved briefing' in cli.run(args(store,'--show'))['message']
    first=store.save(value(),None)['revisions'][-1]
    store.record_analysis(first,{'ai_status':'partial'})
    store.save(value('changed'),first['digest'])
    before=store.path.read_bytes()
    result=cli.run(args(store,'--show'))
    assert result['analysis_stale'] and 'outdated' in cli.render(result)
    assert store.path.read_bytes()==before


def test_analyze_deterministic_and_fake_ai(store,monkeypatch):
    from forensic_assistant.ai.backend import ModelBackend
    from forensic_assistant.ai import settings
    store.save(value(),None)
    calls=[]
    monkeypatch.setattr(settings,'load',lambda:{**settings.defaults(),'provider':'openai','model':'fake','cloud_acknowledged':True})
    monkeypatch.setenv('OPENAI_API_KEY','synthetic')
    monkeypatch.setattr(ModelBackend,'complete',lambda *a:(calls.append(a) or '{"items":[]}'))
    p=cli.run(args(store,'--analyze','--deterministic'))
    assert not calls and p['inputs']=={'narrative':'sample.ps1'} and p['saved_briefing']['revision']==1
    p=cli.run(args(store,'--analyze'))
    assert len(calls)==1 and p['ai_status']=='success'
    assert len(store.load()['analyses'])==2
    with pytest.raises(ValueError,match='revision'):
        cli.run(args(store,'--analyze','--discover','--revision','2'))
    assert len(calls)==1


def test_import_explicit_and_legacy_transient(store):
    before=store.case.read_bytes()
    assert cli.run(args(store,'--text','sample.ps1'))['leads']
    assert not store.root.exists()
    a=args(store,'--text','sample.ps1','--save');a._confirm=lambda p:'yes'
    assert cli.run(a)['revision']['content']['narrative']=='sample.ps1'
    assert store.case.read_bytes()==before


@pytest.mark.parametrize('text',['x'*32769,'a\0b'],ids=['oversized','nul'])
def test_bad_content(store,text):
    with pytest.raises(ValueError):store.save(value(text),None)
    assert not store.root.exists()


@pytest.mark.parametrize('mode',['changed','unchanged','cancel','failure','malformed'])
def test_editor_private_and_no_shell(store,monkeypatch,mode):
    current=value('original');current['answers']['people']='retained'
    monkeypatch.setattr(workflow,'editor_args',lambda p:['fake-editor',str(p)])
    class Process:
        def __init__(self,argv,**kwargs):
            assert kwargs=={'shell':False}
            self.path=Path(argv[1])
            assert self.path.parent.parent==store.case.parent
            if mode=='changed':self.path.write_bytes('\ufeffnew\r\ntext'.encode())
            if mode=='malformed':self.path.write_bytes(b'\xff')
        def wait(self):return 1 if mode=='failure' else 0
    monkeypatch.setattr(workflow.subprocess,'Popen',Process)
    if mode in ('failure','malformed'):
        with pytest.raises(ValueError):workflow.edit(store,current,lambda p:'yes')
    else:
        result=workflow.edit(store,current,lambda p:'no' if mode=='cancel' else 'yes')
        if mode=='cancel':assert result is None
        else:
            assert result['answers']==current['answers']
            assert result['narrative']==('\ufeffnew\r\ntext' if mode=='changed' else 'original')
    assert not list(store.case.parent.glob('.briefing-edit-*'))
    assert not store.root.exists()


def test_editor_interrupt_and_config_argv(store,monkeypatch,tmp_path):
    exe=tmp_path/'editor.exe';exe.write_bytes(b'synthetic, never executed')
    monkeypatch.setenv('LOCARD_BRIEFING_EDITOR',json.dumps([str(exe),'--wait','{file}']))
    path=tmp_path/'untrusted & text.txt'
    assert workflow.editor_args(path)==[str(exe),'--wait',str(path)]
    monkeypatch.setenv('LOCARD_BRIEFING_EDITOR','"not an argument array"')
    with pytest.raises(ValueError):workflow.editor_args(path)
    monkeypatch.setattr(workflow,'editor_args',lambda p:['fake',str(p)])
    stopped=[]
    class Process:
        def __init__(self,*a,**k):pass
        def wait(self,timeout=None):
            if timeout is None:raise KeyboardInterrupt()
        def poll(self):return None
        def terminate(self):stopped.append(True)
    monkeypatch.setattr(workflow.subprocess,'Popen',Process)
    with pytest.raises(KeyboardInterrupt):workflow.edit(store,value(),lambda p:'yes')
    assert stopped and not list(store.case.parent.glob('.briefing-edit-*'))


def test_copied_sidecar_rejected_and_tamper_detected(store,tmp_path):
    import shutil
    state=store.save(value(),None)
    other=tmp_path/'other.db';db=connect(other);db.close()
    second=storage.Store(other)
    shutil.copytree(store.root,second.root)
    with pytest.raises(ValueError,match='identity'):second.load()
    state['revisions'][0]['content']['narrative']='tampered'
    store.path.write_text(json.dumps(state))
    with pytest.raises(ValueError,match='digest'):store.load()


def test_read_only_state_and_editor_options_never_run_discovery(store,monkeypatch):
    monkeypatch.setattr(briefing,'discover',lambda *a:pytest.fail('unauthorized discovery'))
    for flag in ('--show','--wizard','--edit'):
        with pytest.raises(ValueError):cli.run(args(store,flag,'--discover'))
    assert not store.root.exists()


def test_all_empty_and_fresh_revision_binding(store):
    first=store.save(value(''),None)['revisions'][-1]
    assert cli.run(args(store,'--show'))['revision']['content']['narrative']==''
    with pytest.raises(ValueError,match='no content'):cli.run(args(store,'--analyze','--deterministic'))
    store.save(value('new.ps1'),first['digest'])
    with pytest.raises(ValueError,match='revision'):
        cli.run(args(store,'--analyze','--deterministic','--discover','--revision','1'))
