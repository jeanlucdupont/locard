"""Known-alias set canonicalization; no provider or forensic database access."""
import copy
import functools
import json
import multiprocessing
from unittest.mock import patch

import pytest
from test_d2_quality import prepared,answer
from test_d2_diagnostics import fixture,sdk_call,sdk_child,USAGE
from test_d2_transport import sdk
from forensic_assistant.investigation_ai import d2_normalization as n,d2_execution as ex,d2_quality as q,d2_diagnostics as diag,d2_result as ipc


def normalized(p,value):
    return ex.validate_model_response(p,json.dumps(value),parent=True)


@pytest.mark.parametrize('key,category',[('e','support'),('c','contrary'),('i','interpretation')])
def test_reference_categories(key,category):
    p=prepared();v=answer()
    if key=='i':
        v['a'][0]['e']=[s['alias'] for s in p.packet['content']['supports']]
        alias=p.packet['content']['interpretations'][0]['alias']
    else:alias=p.packet['content']['supports'][0]['alias']
    v['a'][0][key]=[alias,alias]
    original=copy.deepcopy(p.packet)
    accepted,info=normalized(p,v)
    assert info['removed'][category]==1 and info['duplicates_removed']==1 and info['canonical_validation']=='passed'
    assert info['contract']==n.VERSION and accepted['original_s3_assessment']==p.history._original
    assert accepted['proposals'][0]['classification']=='mechanically_accepted_unverified'
    assert p.packet==original
    assert alias not in json.dumps(info)


def test_order_idempotence_and_account_boundaries():
    p=prepared();v=answer();v['a'][0]['e']=['O3','O1','O3'];v['a'][0]['c']=['O1','O1']
    other=copy.deepcopy(v['a'][0]);other['s']='Another possible explanation.';v['a'].append(other)
    a,info=n.canonicalize(json.dumps(v),p.packet)
    b,second=n.canonicalize(json.dumps(a),p.packet)
    assert a==b and a['a'][0]['e']==['O3','O1'] and a['a'][1]['e']==['O3','O1']
    assert a['a'][0]['c']==['O1'] and info['duplicates_removed']==4 and not second['occurred']


@pytest.mark.parametrize('aliases,code',[
    (['O999','O999'],'unknown_support'),(['O1','O1','O999'],'unknown_support'),
    (['O1','o1'],'unknown_support'),(['O1','O1 '],'unknown_support'),
    (['other:O1'],'unknown_support'),(['界'],'unknown_support'),([1,1],'wrong_type'),
    (['O1']*7,'item_count'),([], 'item_count')])
def test_raw_and_membership_boundaries(aliases,code):
    p=prepared();v=answer();v['a'][0]['e']=aliases
    with pytest.raises(ValueError) as caught:normalized(p,v)
    detail=diag.failure(caught.value,received=True,reported=USAGE)
    assert detail['code']==code and detail['normalization']['duplicates_removed']==0
    assert detail['normalization']['canonical_validation']=='not_attempted'


def test_duplicate_keys_are_not_repaired():
    with pytest.raises(ValueError) as caught:ex.validate_model_response(prepared(),'{"v":"d2q1","v":"d2q1"}',parent=True)
    assert diag.failure(caught.value)['code']=='duplicate_key'


def test_incomplete_interpretation_after_dedup():
    p=prepared();v=answer();v['a'][0]['e']=['O1','O1'];v['a'][0]['i']=['I1','I1']
    with pytest.raises(ValueError) as caught:normalized(p,v)
    detail=diag.failure(caught.value)
    assert detail['code']=='incomplete_interpretation'
    assert detail['normalization']['duplicates_removed']==2 and detail['normalization']['canonical_validation']=='failed'


def test_unicode_byte_limit_after_normalization():
    p=prepared();v=answer();v['a'][0]['e']=['O1','O1'];v['a'][0]['s']='界'*134
    with pytest.raises(ValueError) as caught:normalized(p,v)
    detail=diag.failure(caught.value)
    assert detail['code']=='utf8_byte_limit' and detail['normalization']['duplicates_removed']==1


def test_wrong_canonical_binding_still_rejected():
    from forensic_assistant.investigation_ai import d2
    p=prepared();v=answer();v['a'][0]['e']=['O1','O1']
    value,_=n.canonicalize(json.dumps(v),p.packet)
    raw=json.loads(q.expand_response(json.dumps(value),p.packet));raw['packet_digest']='0'*64
    with pytest.raises(ValueError,match='D2_RESPONSE_REQUEST_BINDING'):
        d2.validate_response(p.packet,json.dumps(raw),p._response_context)


def test_only_registered_paths():
    p=prepared();v=answer();v['a'][0]['a']='O1 O1';v['a'][0]['s']='Same words same words'
    value,info=n.canonicalize(json.dumps(v),p.packet)
    assert value==v and not info['occurred']
    v['a'].append(copy.deepcopy(v['a'][0]))
    with pytest.raises(ValueError) as caught:normalized(p,v)
    assert diag.failure(caught.value)['code']=='duplicate_item'


@pytest.mark.parametrize('key,count',[('e',7),('c',7),('i',5)])
def test_all_raw_array_limits(key,count):
    p=prepared();v=answer();v['a'][0][key]=['I1' if key=='i' else 'O1']*count
    with pytest.raises(ValueError) as caught:normalized(p,v)
    assert diag.failure(caught.value)['code']=='item_count'
    assert caught.value.d2_normalization['duplicates_removed']==0


def test_raw_response_size_bound():
    with pytest.raises(ValueError) as caught:ex.validate_model_response(prepared(),' '*16385,parent=True)
    assert diag.failure(caught.value)['code']=='utf8_byte_limit'


def test_different_record_aliases_are_not_merged():
    p=prepared();v=answer();v['a'][0]['e']=['O1','O2','O1']
    # Aliases refer to separate original fields even if their displayed values match.
    value,info=n.canonicalize(json.dumps(v),p.packet)
    assert value['a'][0]['e']==['O1','O2'] and info['duplicates_removed']==1


@pytest.mark.parametrize('bad',['extra','version','counts','occurred'])
def test_receipt_closed(bad):
    value=n.receipt()
    if bad=='extra':value['aliases']=['O1']
    if bad=='version':value['contract']='other'
    if bad=='counts':value['removed']['support']=33
    if bad=='occurred':value['occurred']=True
    with pytest.raises(ValueError):n.validate_receipt(value)


@pytest.mark.parametrize('family',['browser','registry','evtx','mft','prefetch'])
def test_generic_families(family):
    from d2_generic_fixtures import context,row
    from test_d2_preview import history
    from test_d2_execution import config
    ctx,_=context([row(family,900,hostname='synthetic',current_path='C:/Synthetic/file',process_name='test.exe')])
    h=history(ctx);p=ex.Prepared(h,h.preview(exploratory=True)['packets'][0],config(),dict(exploratory=True),profile=q.VERSION)
    v=answer();alias=p.packet['content']['supports'][0]['alias'];v['a'][0]['e']=[alias,alias]
    result,info=normalized(p,v)
    assert info['duplicates_removed']==1 and len(result['proposals'][0]['dependencies'])==1


def duplicate_fixture(name,p):
    body=fixture('inference',p);value=json.loads(body['choices'][0]['message']['content'])
    value['a'][0]['e']=['O1','O1']
    if name=='missing_premises':value['a'][0]['i']=['I1','I1']
    body['choices'][0]['message']['content']=json.dumps(value)
    return body


@pytest.mark.parametrize('name',['accepted','missing_premises'])
def test_actual_sdk(sdk,name):
    p=prepared()
    with patch('test_d2_diagnostics.fixture',duplicate_fixture):response=sdk_call(name,p,sdk)
    assert response['usage']==USAGE
    if name=='accepted':
        result,info=ex.validate_model_response(p,response['text'],parent=True)
        assert info['duplicates_removed']==1 and len(result['proposals'][0]['dependencies'])==1
    else:
        with pytest.raises(ValueError) as caught:ex.validate_model_response(p,response['text'],parent=True)
        assert diag.failure(caught.value)['code']=='incomplete_interpretation'


def duplicate_child(name,connection,gate,request):
    with patch('test_d2_diagnostics.fixture',duplicate_fixture):sdk_child(name,connection,gate,request)


@pytest.mark.parametrize('name',['accepted','missing_premises'])
def test_windows_spawn(sdk,monkeypatch,name):
    p=prepared();monkeypatch.setattr(ex,'_child',functools.partial(duplicate_child,name))
    result=ex.execute(ex.authorize(p,lambda _:True))
    assert result['attempts']==1 and result['lookups']==0 and result['usage']==USAGE
    assert result['cleanup']=='confirmed' and not multiprocessing.active_children()
    info=result['diagnostic']['normalization']
    assert info['duplicates_removed']==(1 if name=='accepted' else 2)
    assert info['canonical_validation']==('passed' if name=='accepted' else 'failed')
    assert result['status']==('accepted' if name=='accepted' else 'rejected')
    if name=='accepted':
        assert result['validated']['original_s3_assessment']==p.history._original
        assert len(result['validated']['proposals'][0]['dependencies'])==1
    else:assert result['diagnostic']['code']=='incomplete_interpretation' and 'validated' not in result
    print('NORMALIZATION_IPC',name,result['ipc_result_bytes'])
