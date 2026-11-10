from copy import deepcopy
import pytest
from forensic_assistant.investigation_ai import organization as o
from forensic_assistant.investigation_ai.transcript import Transcript,load
from test_synthesis_consumer import execute


@pytest.mark.parametrize('failure',['none','anchor','checkpoint','cancel','resource'])
def test_finalization_properties_are_separate(tmp_path,monkeypatch,failure):
    original=Transcript.append;committed=[]
    def append(self,kind,data,terminal=False):
        if kind=='organization_final' and failure in ('anchor','cancel'):
            if failure=='cancel':raise KeyboardInterrupt()
            raise OSError('pre-I/O synthetic failure')
        if kind=='organization_checkpoint' and data['final'] and failure=='checkpoint':raise OSError()
        value=original(self,kind,data,terminal)
        if kind=='organization_checkpoint':committed.append(deepcopy(data))
        return value
    monkeypatch.setattr(Transcript,'append',append)
    update=o.Live.update
    def limited(self,source_update,**kw):
        if failure=='resource' and kw.get('final'):kw['deadline']=0
        return update(self,source_update,**kw)
    monkeypatch.setattr(o.Live,'update',limited)
    if failure=='cancel':
        with pytest.raises(KeyboardInterrupt):execute(tmp_path)
        folder=next((tmp_path/'runs').iterdir());rid=folder.name
    else:
        result,*_=execute(tmp_path);rid=result['investigation_id']
    view=o.reconstruct(tmp_path/'runs',rid)
    f=view['finalization']
    assert f['contract']==o.FINALIZATION
    assert f['anchor_committed']==(failure in ('none','checkpoint'))
    assert f['checkpoint_committed']==(failure=='none')
    assert f['terminal_present']==(failure!='cancel')
    assert f['final_s3_available']==(failure!='cancel')
    assert view['incomplete']==(failure!='none')
    assert view['state_digest']==committed[-1]['result_digest']
    assert f['forensic_completeness']=='not_established'


def test_false_completion_diagnostic_rejected(tmp_path):
    from test_organization import rehash
    result,*_=execute(tmp_path);root=tmp_path/'runs';rid=result['investigation_id']
    manifest,events=load(root,rid)
    events[-1]['data']['organization']['finalization']['anchor']=False
    rehash(root/rid,manifest,events)
    with pytest.raises(ValueError,match='finalization'):o.reconstruct(root,rid)
