import pytest
from v1_fixtures import database,process
from forensic_assistant.semantic.index import eligible_ids

def test_semantic_filters_are_sql_constraints():
    db=database();a=process(db,1,'100',name='powershell.exe',host='ONE',time='14:30:00')
    b=process(db,2,'200',name='cmd.exe',host='TWO',time='14:31:00')
    assert eligible_ids(db,{'process':'powershell.exe'})=={a['id']}
    assert eligible_ids(db,{'hostname':'two','strict_host':True})=={b['id']}
    assert eligible_ids(db,{'artifact':'registry'})==set()
    assert eligible_ids(db,{'path':"x' OR 1=1 --"})==set()
    with pytest.raises(ValueError):eligible_ids(db,{'start':'2020-01-02T00:00:00Z','end':'2020-01-01T00:00:00Z'})

def test_tokenizer_never_loads_for_bad_model(tmp_path):
    from forensic_assistant.semantic.model import LocalModel
    with pytest.raises(ValueError,match='unavailable'):LocalModel(tmp_path)
