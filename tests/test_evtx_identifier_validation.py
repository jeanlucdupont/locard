import json
from contextlib import closing
import pytest
from forensic_assistant.database.db import connect
from forensic_assistant.ingest.evtx import ingest_file,ParsedRecord
from forensic_assistant.ingest.validation import LABEL,is_identifier_note
from forensic_assistant.retrieval.evidence import get_evidence,EvidenceQueries
from forensic_assistant.retrieval.search_display import render as search
from forensic_assistant.retrieval.show_display import render as show
from forensic_assistant.interactive.creation import summarize
from test_ingest import xml


@pytest.mark.parametrize('value,header,errors,notes',[(1122,1122,0,0),(1122,1,0,1),(None,1,1,0),('invalid',1,1,0),(-1,1,1,0)])
def test_identifier_cases(tmp_path,value,header,errors,notes):
    source=tmp_path/'synthetic.evtx';source.write_bytes(b'synthetic')
    raw=xml(record_id=value)
    if value is None:raw=raw.replace('<EventRecordID>None</EventRecordID>','')
    def reader(path):yield ParsedRecord(4608,header,raw)
    with closing(connect(tmp_path/'case.db')) as db:
        result=ingest_file(db,source,reader=reader)
        assert result['inserted']==1 and result['errors']==errors
        assert result['status']==('partial' if errors else 'complete')
        assert result['validation_notes']==({LABEL:notes} if notes else {})
        row=db.execute('select * from events').fetchone()
        assert row['record_id']==(value if isinstance(value,int) else None)
        assert row['record_offset']==4608 and row['raw_xml']==raw
        warnings=json.loads(row['normalization_warnings_json'])
        assert sum(map(is_identifier_note,warnings))==notes
        if notes:
            assert 'header=1; xml=1122; offset=4608' in warnings[-1]
            evidence=get_evidence(db,row['id'],True)
            assert warnings[-1] in evidence['warnings']
            assert LABEL not in search(dict(records=[evidence],total=1,offset=0))
            assert 'Validation: '+warnings[-1] in show(evidence)
        if value=='invalid':assert any('Invalid integer' in w for w in warnings)
        again=ingest_file(db,source,reader=reader)
        assert again['inserted']==0 and again['duplicates']==1
        assert dict(db.execute('select * from events').fetchone())==dict(row)


def test_repeated_summary_and_failure_paths(tmp_path,capsys):
    source=tmp_path/'synthetic.evtx';source.write_bytes(b'synthetic');case=tmp_path/'case.db'
    reports=[]
    def reader(path):
        for i in range(3):yield ParsedRecord(4608+i*1024,i+1,xml(record_id=1122+i))
    with closing(connect(case)) as db:
        result=ingest_file(db,source,reader=reader,reporter=reports.append)
        assert result['errors']==0 and result['validation_notes']=={LABEL:3} and not reports
        assert EvidenceQueries(db).search().total==3
    summarize(case);text=capsys.readouterr().out
    assert text.count(LABEL)==1 and ': 3 records' in text and 'recorded errors: 0' in text
    assert 'Recorded limitation:' not in text
    def bad_reader(path):
        yield ParsedRecord(7000,4,error='Structural verification failed')
        yield ParsedRecord(8000,5,'<broken')
    with closing(connect(case)) as db:
        result=ingest_file(db,source,reader=bad_reader)
        assert result['errors']==2 and result['status']=='partial' and result['validation_notes']=={}
        assert {r[0] for r in db.execute('select stage from ingestion_errors')}=={'parse','normalize'}


def test_source_change_still_rejects(tmp_path):
    source=tmp_path/'synthetic.evtx';source.write_bytes(b'before')
    def reader(path):
        yield ParsedRecord(4608,1,xml(record_id=1122))
        path.write_bytes(b'after')
    with closing(connect(':memory:')) as db:
        result=ingest_file(db,source,reader=reader)
        assert result['status']=='changed' and result['errors']==1
        assert db.execute('select count(*) from events').fetchone()[0]==0
