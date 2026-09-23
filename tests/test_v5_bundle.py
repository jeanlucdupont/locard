import json
import pytest
from forensic_assistant.reporting.bundle import generate,inspect,validate
from forensic_assistant.reporting.model import canonical
from test_v4_worker import make_case

def test_offline_bundle_integrity_and_scope(tmp_path):
    case=tmp_path/'case.db';event=make_case(case);output=tmp_path/'report'
    generate(case,output,evidence_ids=[event['id']],metadata={'title':'<script>alert(1)</script>'})
    report,manifest=inspect(output)
    assert manifest['input_mode']=='explicit_evidence_ids'
    html=(output/'report.html').read_text()
    assert '<script>' not in html and '&lt;script&gt;' in html and 'No complete investigation' in html
    assert validate(output,case=case)['evidence_grounding']=='PASS'
    assert validate(output)['evidence_grounding']=='NOT_CHECKED'
    with pytest.raises(ValueError,match='already exists'):generate(case,output,evidence_ids=[event['id']])
    with (output/'report.html').open('ab') as stream:stream.write(b'tampered')
    result=validate(output)
    assert result['file_integrity']=='FAIL' and result['structure']=='NOT_CHECKED'

def test_redaction_suppresses_payloads_across_all_outputs(tmp_path):
    import sqlite3
    case=tmp_path/'case.db';event=make_case(case)
    db=sqlite3.connect(case);db.execute("UPDATE events SET username=?,command_line=?",('SecretAnalyst','run SecretPayload'));db.commit();db.close()
    output=tmp_path/'redacted'
    generate(case,output,evidence_ids=[event['id']],redaction='identifiers',metadata={'analyst_name':'SecretAnalyst'})
    for path in output.iterdir():
        assert b'SecretAnalyst' not in path.read_bytes() and b'SecretPayload' not in path.read_bytes()
    assert inspect(output)[0]['data']['redaction_notice']
    assert validate(output,case=case)['evidence_grounding']=='PASS'

def test_publication_failure_leaves_no_complete_bundle(tmp_path,monkeypatch):
    import forensic_assistant.reporting.bundle as bundle
    case=tmp_path/'case.db';event=make_case(case)
    def fail(*args):raise OSError('Synthetic disk full')
    monkeypatch.setattr(bundle.os,'fsync',fail)
    with pytest.raises(OSError):generate(case,tmp_path/'report',evidence_ids=[event['id']])
    assert not (tmp_path/'report').exists() and not list(tmp_path.glob('.locard-report-*'))
