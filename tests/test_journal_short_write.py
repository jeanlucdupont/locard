"""Exact binary write-count faults in disposable journals; no real evidence."""
from copy import deepcopy
from pathlib import Path
import pytest
from forensic_assistant.investigation_ai import transcript as t
from test_journal_publication import Stream


@pytest.mark.parametrize('boundary',['manifest','event'])
@pytest.mark.parametrize('result',['zero','partial','none','negative','oversize','boolean','float','complete'])
def test_exact_write_result(tmp_path,monkeypatch,boundary,result):
    journal=t.Transcript(tmp_path,{'note':'Unicode: 界 é'})
    journal.append('accepted',{})
    before=deepcopy(journal.last_confirmed)
    manifest_before=(journal.path/'manifest.json').read_bytes()
    writes=[];replacements=[]
    class Writer(Stream):
        def write(self,raw):
            writes.append(len(raw))
            if result=='zero':return 0
            if result=='partial':return self.wrapped.write(raw[:len(raw)//2])
            if result=='none':return None
            if result=='negative':return -1
            if result=='oversize':return len(raw)+1
            if result=='boolean':return True
            if result=='float':return float(self.wrapped.write(raw))
            return self.wrapped.write(raw)
    original_open=Path.open;original_replace=t.os.replace
    def opened(path,*args,**kw):
        stream=original_open(path,*args,**kw)
        return Writer(stream,None,None) if path.name=='manifest.tmp' and args and args[0]=='xb' else stream
    def replace(*args):
        replacements.append(1);return original_replace(*args)
    if boundary=='manifest':monkeypatch.setattr(Path,'open',opened)
    else:journal.stream=Writer(journal.stream,None,None)
    monkeypatch.setattr(t.os,'replace',replace)
    if result=='complete':
        journal.append('attempt',{'text':'界'})
        assert journal.publication['status']=='confirmed'
        assert journal.count==before['count']+1
        assert len(t.load(tmp_path,journal.id)[1])==2
        assert len(replacements)==1
        journal.close()
    else:
        with pytest.raises(t.JournalPublicationError):journal.append('attempt',{'text':'界'})
        assert journal.publication['status']=='uncertain'
        assert journal.last_confirmed==before
        assert journal.count==before['count'] and journal.chain==before['chain']
        assert not replacements
        assert (journal.path/'manifest.json').read_bytes()==manifest_before
        files={p.name:p.read_bytes() for p in journal.path.iterdir() if p.is_file()}
        with pytest.raises(t.JournalPublicationError):journal.append('retry',{})
        assert files=={p.name:p.read_bytes() for p in journal.path.iterdir() if p.is_file()}
        if boundary=='manifest' or result in ('partial','float'):
            with pytest.raises(ValueError):t.load(tmp_path,journal.id)
        else:assert len(t.load(tmp_path,journal.id)[1])==1
    assert len(writes)==1  # no write-all spin or automatic append retry


def test_manifest_flush_failure(tmp_path,monkeypatch):
    j=t.Transcript(tmp_path,{})
    original=Path.open
    def opened(path,*a,**kw):
        stream=original(path,*a,**kw)
        return Stream(stream,'flush',OSError) if path.name=='manifest.tmp' and a and a[0]=='xb' else stream
    monkeypatch.setattr(Path,'open',opened)
    with pytest.raises(t.JournalPublicationError):j.append('attempt',{})
    assert j.count==0 and j.publication['status']=='uncertain'
    with pytest.raises(ValueError):t.load(tmp_path,j.id)


def test_loader_does_not_accept_incomplete_published_manifest(tmp_path):
    j=t.Transcript(tmp_path,{})
    j.append('accepted',{});j.close()
    # Isolated malformed-file fixture, never an original transcript.
    (j.path/'manifest.json').write_bytes(b'{"format":')
    with pytest.raises(ValueError):t.load(tmp_path,j.id)


@pytest.mark.parametrize('boundary',['initial','terminal_status'])
def test_other_manifest_publications_reject_short_write(tmp_path,monkeypatch,boundary):
    j=t.Transcript(tmp_path,{}) if boundary=='terminal_status' else None
    original=Path.open;calls=[]
    class Short(Stream):
        def write(self,raw):return 0
    def opened(path,*a,**kw):
        stream=original(path,*a,**kw)
        if path.name=='manifest.tmp' and a and a[0]=='xb':
            calls.append(1)
            if boundary=='initial' or len(calls)==2:return Short(stream,None,None)
        return stream
    monkeypatch.setattr(Path,'open',opened)
    if boundary=='initial':
        with pytest.raises(OSError,match='Incomplete journal write'):t.Transcript(tmp_path,{})
        assert not list(tmp_path.glob('*/manifest.json'))
        assert len(calls)==1
    else:
        with pytest.raises(t.JournalPublicationError):j.finish({'termination':'done'})
        assert j.publication['status']=='uncertain' and j.count==1
        assert j.last_confirmed['count']==1  # terminal append succeeded first
        manifest,events=t.load(tmp_path,j.id)
        assert manifest['status']=='RUNNING' and events[-1]['kind']=='terminal'
        assert len(calls)==2
