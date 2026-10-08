"""Synthetic SCM installations preserve configuration without claiming execution."""
import json
import pytest
from xml.sax.saxutils import escape
from forensic_assistant.database.db import connect,register_source,insert_events
from forensic_assistant.ingest.normalize import normalize
from forensic_assistant.ingest.service import fields,NOTE
from forensic_assistant.retrieval.evidence import get_evidence,EvidenceQueries
from forensic_assistant.retrieval.show_display import render as show
from forensic_assistant.retrieval.search_display import render as search
from forensic_assistant.retrieval.evtx_display import render_timeline
from forensic_assistant.detections.engine import detections
from forensic_assistant.cli import build_parser
from forensic_assistant.v2_cli import dispatch
from test_ingest import xml,SHA

FIELDS={'ServiceName':'example-service','ImagePath':r'C:\Windows\System32\example.exe',
        'ServiceType':'user mode service','StartType':'auto start','AccountName':'LocalSystem'}


def raw(data=None,provider='Service Control Manager',channel='System',event_id=7045):
    return xml(event_id,provider,channel,''.join(f'<Data Name="{k}">{escape(v)}</Data>' for k,v in (data if data is not None else FIELDS.items())))


def add(db,text=None,offset=512):
    event=normalize(text or raw(),SHA,'synthetic.evtx',offset)
    with db:
        register_source(db,SHA,1,'synthetic.evtx');insert_events(db,[event])
    return get_evidence(db,event.id,True)


def test_fields_identity_timestamp_and_show():
    db=connect(':memory:');record=add(db)
    assert record['artifact_type']==record['kind']=='service'
    assert record['service_name']=='example-service'
    assert record['username'] is None and record['process_name'] is None
    assert record['service_installation']==dict(service_name='example-service',image_path=FIELDS['ImagePath'],
        service_type='user mode service',start_type='auto start',account='LocalSystem')
    assert record['raw_xml']==raw() and len(json.loads(record['event_data_json']))==5
    assert [t['slot'] for t in record['timestamps']]==['SystemTime']
    assert record['timestamp_utc']=='2026-09-15T14:30:55.123456700Z'
    text=show(record)
    for expected in ('7045','Service Control Manager','System','Computer: PC.example','EventRecordID: 7',
                     'Service name: example-service',FIELDS['ImagePath'],'Service type: user mode service',
                     'Start type: auto start','Account: LocalSystem',NOTE):
        assert expected in text
    assert 'Unmapped event' not in text
    assert db.execute('PRAGMA user_version').fetchone()[0]==4
    db.close()


@pytest.mark.parametrize('provider,channel,event_id',[('Other','System',7045),('Service Control Manager','Other',7045),('Service Control Manager','System',7044)])
def test_provider_channel_id_gates(provider,channel,event_id):
    event=normalize(raw(provider=provider,channel=channel,event_id=event_id),SHA,'synthetic.evtx',512)
    assert event.artifact_type is None


def test_duplicate_fields_remain_ambiguous_and_raw_retained():
    event=normalize(raw(list(FIELDS.items())+[('ImagePath','other'),('ServiceName','other')]),SHA,'synthetic.evtx',512)
    assert event.service_name is None
    assert fields(event.as_dict())['image_path'] is None
    assert len(json.loads(event.event_data_json))==7
    assert len(json.loads(event.normalization_warnings_json))==2


def test_search_services_timeline_detection_and_order():
    db=connect(':memory:');record=add(db)
    args=build_parser().parse_args(['search','--artifact','evtx','--event-id','7045','--ids'])
    result,_=dispatch(db,args)
    text=search(result,ids=True)
    assert record['id'] in text and 'ServiceInstall' in text and FIELDS['ImagePath'] in text
    args=build_parser().parse_args(['search','--kind','services'])
    result,_=dispatch(db,args)
    assert [r['id'] for r in result['records']]==[record['id']]
    timeline=EvidenceQueries(db).search(timeline=True)
    text=render_timeline(timeline.as_dict())
    assert 'ServiceInstall' in text and 'Image: '+FIELDS['ImagePath'] in text and 'Account: LocalSystem' in text
    findings=detections(db,rule_id='LOCARD-SVC-001')['detections']
    assert len(findings)==1 and findings[0]['rule_id']=='LOCARD-SVC-001' and '7045' in findings[0]['reason']
    # Existing 4697 remains the same service observation rule, not a second rule.
    add(db,xml(4697,data='<Data Name="ServiceName">old-service</Data>'),1024)
    assert len(detections(db,rule_id='LOCARD-SVC-001')['detections'])==2
    db.close()



def test_host_names_not_aliased():
    db=connect(':memory:')
    a=add(db,raw().replace('PC.example','HOST.example'))
    b=add(db,raw().replace('PC.example','HOST'),1024)
    assert a['computer']=='HOST.example' and b['computer']=='HOST'
    assert a['hostname']!=b['hostname']
    db.close()
