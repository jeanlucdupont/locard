"""6.83 canonical document, review and JSON exchange; disposable cases only."""
import copy
import json
from pathlib import Path
import pytest
from forensic_assistant import briefing_canonical as c,briefing as b,briefing_cli as cli
from forensic_assistant.briefing_store import content,FIELDS,sources
from test_briefing_persistence import store,args
from test_briefing_semantics import candidate
from test_briefing import Fake


def entry(value='sample.ps1',kind='filename',status='provided'):
    return {'status':status,'value':value if status not in ('unknown','not_provided','not_applicable') else '',
            'kind':kind,'statement':value,'polarity':'reported','note':'Unverified analyst assertion'}


def test_all_categories_and_statuses():
    doc=c.empty()
    assert len(doc['categories'])==18
    for key in doc['categories']:doc['categories'][key]=[entry('reported information','activity')]
    for i,status in enumerate(c.STATES):doc['categories']['context'].append(entry('Analyst statement '+str(i),'activity',status))
    assert c.check(doc)==doc
    rendered=c.render({'document':doc})
    for label in c.CATEGORIES.values():assert label in rendered


def test_sparse_missing_unknown_and_person_not_account():
    p=b.extract('Callie Wade. Timezone unknown.')
    person=candidate(p,'person','Callie Wade');person.update(category='person',status='provided')
    unknown=candidate(p,'timezone','Timezone unknown');unknown.update(category='when',status='unknown')
    b.interpret(p,Fake({'items':[],'candidates':[person,unknown]}))
    proposed=c.build(p);doc=proposed['document']
    assert doc['categories']['person'][0]['value']=='Callie Wade'
    assert doc['categories']['account']==[]
    assert doc['categories']['when'][0]['status']=='unknown' and doc['categories']['when'][0]['value']==''
    assert 'UTC' not in c.render(proposed)
    assert 'extraction may have omitted' in c.render(proposed)


def test_ai_omissions_explicit_and_summary_validated():
    text='A reported alert; investigate whether execution occurred.';p=b.extract(text)
    b.interpret(p,Fake({'items':[],'candidates':[], 'summary':{'text':'The analyst reported an alert. Execution remains uncertain.',
        'source_ids':[p['source_units'][0]['id']],'uncertainty':'Not independently verified'}}))
    doc=c.build(p)['document']
    assert doc['summary']['status']=='proposed' and not doc['categories']['person'] and not doc['categories']['objectives']
    p=b.extract(text)
    b.interpret(p,Fake({'items':[],'summary':{'text':'invented.exe executed.',
        'source_ids':[p['source_units'][0]['id']],'uncertainty':'Unknown'}}))
    assert c.build(p)['document']['summary']['text'].startswith('invented.exe')
    assert p['proposed_summary']['narrative_review'][0]['rule']=='possible_identifier_mismatch'
    assert not any('invented.exe' in str(lead) for lead in p['leads'])


@pytest.mark.parametrize('value',['a','an','per-user','type-library'])
def test_false_host_cannot_be_a_lead(value):
    p=b.extract('The computer was '+value+'.')
    assert not [l for l in p['leads'] if l['type']=='hostname']
    b.interpret(p,Fake({'items':[],'candidates':[candidate(p,'hostname',value)]}))
    assert not p['ai_candidates']


def test_accept_correct_add_reject_summary_and_originals(store):
    original=content(dict.fromkeys(FIELDS,''),'Original narrative retained.')
    first=store.save(original,None)['revisions'][0]
    p=b.extract('sample.ps1');proposed=c.build(p)
    read=iter(['correct','files','1','provided','filename','corrected.ps1','add','objectives','provided','objective','Determine execution','accept'])
    accepted=c.review(proposed,lambda prompt:next(read))
    new=copy.deepcopy(original);new['canonical']=accepted
    state=store.save(new,first['digest'])
    assert state['revisions'][0]==first
    assert state['revisions'][1]['content']['narrative']==original['narrative']
    assert state['revisions'][1]['content']['canonical']['document']['categories']['files'][0]['value']=='corrected.ps1'
    assert 'corrected.ps1' in sources(state['revisions'][1]).values()
    assert c.review(proposed,lambda prompt:'finish') is None
    proposed['document']['summary']={'text':'Proposed','statement':'Source','status':'proposed'}
    read=iter(['reject-summary','accept'])
    assert c.review(proposed,lambda prompt:next(read))['document']['summary']['status']=='rejected'


def test_json_roundtrip_confirmation_no_overwrite(store,tmp_path):
    raw=store.case.read_bytes();doc=c.empty();doc['categories']['files']=[entry()]
    path=tmp_path/'input.json';path.write_text(json.dumps(doc),encoding='utf-8')
    a=args(store,'--import-json',str(path));a._confirm=lambda p:'n'
    cli.run(a);assert store.load() is None
    a._confirm=lambda p:'y';cli.run(a)
    saved=store.load()['revisions'][-1]
    out=tmp_path/'out.json';cli.run(args(store,'--export-json',str(out)))
    assert json.loads(out.read_text())==doc
    assert set(json.loads(out.read_text()))=={'format','categories','summary'}
    with pytest.raises(ValueError,match='already exists'):cli.run(args(store,'--export-json',str(out)))
    assert store.case.read_bytes()==raw
    assert saved['content']['canonical']['verification']=='UNVERIFIED ANALYST INPUT'


@pytest.mark.parametrize('alter',[
 lambda d:d.update(approved=True),
 lambda d:d['categories']['files'].append(entry('999.1.2.3','ipv4')),
 lambda d:d['categories']['files'].append({**entry('Timezone unknown','timezone','unknown'),'value':'UTC'}),
 lambda d:d['categories']['files'].append({**entry(),'source_ids':['S-invented']})])
def test_closed_import_contract(alter):
    doc=c.empty();alter(doc)
    with pytest.raises(ValueError):c.check(doc)


def test_malformed_import_preserves_revision(store,tmp_path):
    state=store.save(content(dict.fromkeys(FIELDS,''),'old'),None)
    path=tmp_path/'bad.json';path.write_text('{bad')
    a=args(store,'--import-json',str(path));a._confirm=lambda p:'y'
    with pytest.raises(ValueError):cli.run(a)
    assert store.load()==state


def test_old_revision_and_optimistic_lock(store):
    old=store.save(content(dict.fromkeys(FIELDS,''),'old'),None)['revisions'][0]
    accepted={**old['content'],'canonical':c.envelope(c.empty())}
    store.save(content(dict.fromkeys(FIELDS,''),'new'),old['digest'])
    with pytest.raises(ValueError,match='changed'):store.save(accepted,old['digest'])
    assert len(store.load()['revisions'])==2


def test_json_exchange_cannot_authorize_search(store,tmp_path):
    with pytest.raises(ValueError,match='cannot combine'):
        cli.run(args(store,'--export-json',str(tmp_path/'x.json'),'--discover','--approve','L-fake'))
    assert not (tmp_path/'x.json').exists()


def test_saved_analysis_acceptance_finish_and_case_hash(store):
    before=store.case.read_bytes()
    original=store.save(content(dict.fromkeys(FIELDS,''),'sample.ps1'),None)['revisions'][0]
    a=args(store,'--analyze','--deterministic');a._confirm=lambda p:'finish'
    result=cli.run(a)
    assert not result['canonical']['accepted'] and len(store.load()['revisions'])==1
    a._confirm=lambda p:'accept';result=cli.run(a)
    assert result['canonical']['accepted'] and len(store.load()['revisions'])==2
    assert store.load()['revisions'][0]==original and store.case.read_bytes()==before
    assert 'discovery' not in result


def test_accepted_person_survives_deterministic_reanalysis(store):
    doc=c.empty();doc['categories']['person']=[entry('Callie Wade','person')]
    store.save({**content(dict.fromkeys(FIELDS,''),'Original'), 'canonical':c.envelope(doc)},None)
    result=cli.run(args(store,'--analyze','--deterministic'))
    assert result['canonical']['document']['categories']['person']==doc['categories']['person']
    assert not result['canonical']['accepted']


def test_multiple_hosts_accounts_urls_and_conflicts():
    doc=c.empty()
    doc['categories']['systems']=[entry('HOST-1','hostname'),entry('HOST-2','hostname','conflicting')]
    doc['categories']['account']=[entry(r'LAB\alice','account'),entry('bob@example.org','account')]
    doc['categories']['websites']=[entry('https://example.org/report?id=2','url'),entry('example.net','domain')]
    assert c.check(doc)==doc
    assert 'conflicting' in c.render({'document':doc})


def test_internal_provenance_tampering_rejected(store):
    doc=c.empty();doc['categories']['files']=[entry()]
    envelope=c.envelope(doc);envelope['provenance']['source_units'][0]['text']='forged'
    with pytest.raises(ValueError,match='provenance'):c.check_envelope(envelope)
    assert not store.root.exists()


def test_empty_accepted_template_does_not_request_provider(store,monkeypatch):
    store.save({**content(dict.fromkeys(FIELDS,''),''),'canonical':c.envelope(c.empty())},None)
    monkeypatch.setattr(b,'interpret',lambda *a,**k:pytest.fail('No provider for empty content'))
    assert cli.run(args(store,'--analyze'))['kind']=='saved_briefing'


def test_output_cannot_poison_sqlite_sidecars(store):
    with pytest.raises(ValueError,match='overlaps'):
        cli.run(args(store,'--export-json',str(store.case)+'-journal'))
    assert not Path(str(store.case)+'-journal').exists()


def test_review_cancellation_does_not_save(store):
    proposal=c.build(b.extract('sample.ps1'))
    with pytest.raises(KeyboardInterrupt):c.review(proposal,lambda p:'cancel')
    assert store.load() is None


def test_openai_nested_optional_fields_decode():
    from forensic_assistant.ai.openai_schema import response
    p=b.extract('sample.ps1');item=candidate(p,'filename','sample.ps1')
    item.update(category=None,status=None)
    raw=json.dumps({'items':[],'candidates':[item],'summary':None})
    parsed=json.loads(response('openai',raw,b.SCHEMA))
    assert 'category' not in parsed['candidates'][0] and 'status' not in parsed['candidates'][0]
    assert 'summary' not in parsed


@pytest.mark.parametrize('value,valid',[('2026-09-30 to 2026-10-01',True),('2026-10-01 to 2026-09-30',False),('2026-99-30 to 2026-10-01',False)])
def test_date_range_is_not_utc_or_search_authority(value,valid):
    doc=c.empty();doc['categories']['when']=[entry(value,'date_range','approximate')]
    if valid:
        assert c.check(doc)==doc
        assert 'UTC' not in c.render({'document':doc})
    else:
        with pytest.raises(ValueError):c.check(doc)
