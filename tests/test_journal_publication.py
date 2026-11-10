"""Disposable derived journals only; no provider or evidence access."""
from copy import deepcopy
from pathlib import Path
import pytest
from forensic_assistant.investigation_ai import transcript as t
from forensic_assistant.investigation_ai import supervision
_real_child=supervision._child


def publication_failure_child(connection,gate,request):
    from forensic_assistant.investigation_ai import controller
    def fail(config,question,root,**kwargs):
        j=t.Transcript(root,{},investigation_id=config['_investigation_id'])
        def broken_manifest():raise OSError('synthetic manifest failure')
        j._manifest=broken_manifest
        j.append('synthetic',{})
    controller.run=fail
    _real_child(connection,gate,request)


def test_supervisor_reports_and_contains_uncertain_publication(tmp_path,monkeypatch):
    from test_autonomous_startup import configured
    from forensic_assistant.investigation_ai.state import Budget
    from forensic_assistant.llm.client import LocalClient
    config=configured(tmp_path,'transcript_init')
    before=Path(config['case_path']).read_bytes()
    monkeypatch.setattr(supervision,'_child',publication_failure_child)
    result=supervision.run(config,config['_stage_a']['objective'],tmp_path/'runs',
                           client=LocalClient(),budget=Budget(seconds=10))
    assert result['termination']=='JOURNAL_PUBLICATION_UNCERTAIN'
    assert result['journal_publication']['confirmed_event_count']==0
    assert result['journal_publication']['stage']=='manifest_publication'
    assert result['startup_diagnostic']['cleanup_confirmed']
    assert not result['transcript_complete'] and not result['findings']
    assert Path(config['case_path']).read_bytes()==before


class Stream:
    def __init__(self, wrapped, stage, error):
        self.wrapped=wrapped;self.stage=stage;self.error=error
    def write(self, data):
        if self.stage=='before_write':raise self.error()
        if self.stage=='partial_write':
            self.wrapped.write(data[:10]);raise self.error()
        return self.wrapped.write(data)
    def flush(self):
        if self.stage=='flush':raise self.error()
        return self.wrapped.flush()
    def fileno(self):return self.wrapped.fileno()
    def close(self):return self.wrapped.close()
    def __enter__(self):return self
    def __exit__(self,*args):self.close()


@pytest.mark.parametrize('error',[OSError,KeyboardInterrupt])
@pytest.mark.parametrize('stage',['before_write','partial_write','flush','event_fsync',
    'manifest_open','manifest_write','manifest_fsync','replace','after_replace'])
def test_publication_fault_poisoning(tmp_path,monkeypatch,stage,error):
    journal=t.Transcript(tmp_path,{})
    journal.append('accepted',{'value':1})
    confirmed=deepcopy(journal.last_confirmed)
    if stage in ('before_write','partial_write','flush'):
        journal.stream=Stream(journal.stream,stage,error)
    original_open=Path.open;original_sync=t.os.fsync;original_replace=t.os.replace
    calls=[]
    def opened(path,*args,**kwargs):
        if path.name=='manifest.tmp' and args and args[0]=='xb':
            if stage=='manifest_open':raise error()
            stream=original_open(path,*args,**kwargs)
            return Stream(stream,'partial_write',error) if stage=='manifest_write' else stream
        return original_open(path,*args,**kwargs)
    def sync(fd):
        calls.append(fd)
        if stage=='event_fsync' and len(calls)==1 or stage=='manifest_fsync' and len(calls)==2:raise error()
        return original_sync(fd)
    def replace(*args):
        if stage=='replace':raise error()
        result=original_replace(*args)
        if stage=='after_replace':raise error()
        return result
    monkeypatch.setattr(Path,'open',opened);monkeypatch.setattr(t.os,'fsync',sync)
    monkeypatch.setattr(t.os,'replace',replace)
    with pytest.raises(t.JournalPublicationError):journal.append('attempt',{'value':2})
    assert journal.publication['status']=='uncertain'
    assert journal.last_confirmed==confirmed
    assert (journal.count,journal.chain,journal.size)==(confirmed['count'],confirmed['chain'],confirmed['size'])
    files={p.name:p.read_bytes() for p in journal.path.iterdir() if p.is_file()}
    for action in (lambda:journal.append('again',{}),lambda:journal.finish({'termination':'success'})):
        with pytest.raises(t.JournalPublicationError):action()
    assert files=={p.name:p.read_bytes() for p in journal.path.iterdir() if p.is_file()}
    if stage=='before_write':
        assert len(t.load(tmp_path,journal.id)[1])==1
    elif stage=='after_replace':
        # Disk may be ahead of the last successfully returned append. Never retry.
        assert len(t.load(tmp_path,journal.id)[1])==2
    else:
        with pytest.raises(ValueError):t.load(tmp_path,journal.id)


def test_admission_failure_is_not_publication_uncertainty(tmp_path):
    j=t.Transcript(tmp_path,{})
    with pytest.raises(ValueError):j.append('too_big',{'text':'a'*(601*1024)})
    assert j.publication['status']=='admission_rejected' and j.count==0
    j.append('small',{});j.finish({'termination':'done'})
    assert len(t.load(tmp_path,j.id)[1])==2


def test_terminal_status_update_failure_keeps_confirmed_terminal(tmp_path,monkeypatch):
    j=t.Transcript(tmp_path,{})
    original=j._manifest;calls=[]
    def manifest():
        calls.append(1)
        if len(calls)==2:raise OSError()
        return original()
    monkeypatch.setattr(j,'_manifest',manifest)
    with pytest.raises(t.JournalPublicationError):j.finish({'termination':'done'})
    assert j.last_confirmed['count']==1
    manifest,events=t.load(tmp_path,j.id)
    assert manifest['status']=='RUNNING' and events[-1]['kind']=='terminal'
    assert j.publication['stage']=='terminal_manifest_publication'


def test_fatal_publication_stops_analysis_and_closes_worker(tmp_path,monkeypatch):
    from test_synthesis_consumer import setup
    from forensic_assistant.investigation_ai import autonomous
    config,worker,client,seen,closed=setup(tmp_path)
    original=t.Transcript._manifest
    def manifest(self):
        if self.count and self.publication.get('attempted_kind')=='validated_delta':raise OSError()
        return original(self)
    monkeypatch.setattr(t.Transcript,'_manifest',manifest)
    with pytest.raises(t.JournalPublicationError):
        autonomous.run(config,config['_stage_a']['objective'],tmp_path/'runs',client=client,worker_factory=worker)
    assert closed
    assert len(client.calls)==2  # decomposition plus first analysis; no retry/B2
    assert len([x for x in seen if x[0]=='show_evidence'])==1


def test_confirmed_append_survives_dependent_commit_exception(tmp_path,monkeypatch):
    from test_synthesis_consumer import execute
    from forensic_assistant.investigation_ai import organization as o
    original=o._Reducer.commit;failed=[]
    def commit(self,prepared):
        if not failed:
            failed.append(1);raise RuntimeError('after durable checkpoint')
        return original(self,prepared)
    monkeypatch.setattr(o._Reducer,'commit',commit)
    result,*_=execute(tmp_path)
    # Live state was not committed. Replay must reject the inconsistent terminal,
    # not erase the checkpoint or silently certify the run.
    with pytest.raises(ValueError):o.reconstruct(tmp_path/'runs',result['investigation_id'])
    _,events=t.load(tmp_path/'runs',result['investigation_id'])
    assert any(e['kind']=='organization_checkpoint' for e in events)
