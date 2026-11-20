"""Provider-free autonomous preflight diagnostics and explicit cache requirements."""
import json
from types import SimpleNamespace
import pytest
from forensic_assistant.ai import readiness, settings, investigation_preflight as p
from forensic_assistant.ai.backend import ModelBackend
from forensic_assistant import activity


def config():
    return {**settings.defaults(),'provider':'openai','model':'unknown-future-model','cloud_acknowledged':True}


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    readiness.reset()
    monkeypatch.setenv('OPENAI_API_KEY','synthetic-secret')
    monkeypatch.setattr(readiness,'check',lambda _: {'readiness_category':'configured'})
    monkeypatch.setattr(ModelBackend,'_cloud',lambda *a,**k:pytest.fail('Unexpected provider request'))
    yield
    readiness.reset()


def test_unverified_not_model_rejected_and_no_provider_call():
    with pytest.raises(p.InvestigationPreflightError) as caught:p.require(config())
    d=caught.value.diagnostic
    assert d['category']=='investigation_compatibility_unverified'
    assert d['provider_requests']==0 and d['evidence_lookups']==0 and d['findings']==[]
    assert 'same Locard session' in d['suggested_action'] and 'ai check --full' in str(caught.value)
    assert d['model']=='unknown-future-model'


@pytest.mark.parametrize('category',['authentication_failed','authorization_failed','model_rejected','unsupported_parameter','structured_output_unsupported','timeout','rate_limited','network_error','structured_validation_failed','response_parse_failed'])
def test_cached_failures_sanitized_and_distinct(monkeypatch,category):
    monkeypatch.setattr(readiness,'status',lambda _:dict(readiness_category=category,readiness_stage='provider_request',readiness_reason='synthetic-secret private evidence',investigation_compatibility='unavailable'))
    with pytest.raises(p.InvestigationPreflightError) as caught:p.require(config())
    d=caught.value.diagnostic
    assert d['category']==category and d['origin']=='cached_diagnostic'
    assert d['prior_diagnostic_stage']=='provider_request'
    assert 'synthetic-secret' not in json.dumps(d) and 'private evidence' not in str(caught.value)


@pytest.mark.parametrize('category',['missing_key','missing_dependency','invalid_configuration'])
def test_local_configuration(monkeypatch,category):
    monkeypatch.setattr(readiness,'check',lambda _: {'readiness_category':category})
    with pytest.raises(p.InvestigationPreflightError) as caught:p.require(config())
    assert caught.value.diagnostic['category']==category
    assert caught.value.diagnostic['origin']=='local'


def test_acknowledgement_and_internal_failure(monkeypatch):
    with pytest.raises(p.InvestigationPreflightError) as caught:p.require({**config(),'cloud_acknowledged':False})
    assert caught.value.diagnostic['category']=='investigation_configuration_required'
    monkeypatch.setattr(readiness,'status',lambda _:(_ for _ in ()).throw(ValueError('synthetic-secret')))
    with pytest.raises(p.InvestigationPreflightError) as caught:p.require(config())
    assert caught.value.diagnostic['category']=='compatibility_check_failed'
    assert 'synthetic-secret' not in str(caught.value)


def test_ready_cache_binding_and_invalidation(monkeypatch):
    c=config();key=readiness.cache_key(c)
    readiness._credentials[key]=readiness.credential_identity(c)
    readiness._cache[key]={'investigation_compatibility':'ready'}
    assert p.require(c) is None
    with pytest.raises(p.InvestigationPreflightError):p.require({**c,'model':'different-model'})
    monkeypatch.setenv('OPENAI_API_KEY','replacement-synthetic-secret')
    with pytest.raises(p.InvestigationPreflightError):p.require(c)
    readiness.reset()
    with pytest.raises(p.InvestigationPreflightError):p.require(c)


def test_failure_audited_required_and_failure_propagated(monkeypatch):
    calls=[]
    monkeypatch.setattr(activity,'event',lambda *a,**k:calls.append((a,k)))
    with pytest.raises(p.InvestigationPreflightError):p.require(config())
    assert calls[0][0]==('INVESTIGATION_PREFLIGHT','failure') and calls[0][1]['required'] is True
    monkeypatch.setattr(activity,'event',lambda *a,**k:(_ for _ in ()).throw(activity.AuditError('unavailable')))
    with pytest.raises(activity.AuditError):p.require(config())


def test_failure_before_approvals_or_investigation(monkeypatch,capsys):
    from forensic_assistant import investigation_workflow as flow,assessment_handoff,assessment_handoff_cli
    monkeypatch.setattr(assessment_handoff,'prepare',lambda *a:dict(assessment_id='synthetic',limitations=[],scope={}))
    monkeypatch.setattr(settings,'load',config)
    monkeypatch.setattr(assessment_handoff_cli,'execute',lambda *a,**k:pytest.fail('Must not start'))
    with pytest.raises(p.InvestigationPreflightError):
        flow.run('synthetic.db','synthetic','neutral question',read=lambda _:pytest.fail('No unnecessary approval'),json_output=True)
    assert not capsys.readouterr().out


@pytest.mark.parametrize('as_json',[False,True])
def test_cli_failure_exit_and_format(monkeypatch,capsys,as_json):
    from forensic_assistant import cli,workflow_cli
    try:p.require(config())
    except p.InvestigationPreflightError as failure:error=failure
    monkeypatch.setattr(workflow_cli,'run',lambda _:(_ for _ in ()).throw(error))
    values=[]
    args=SimpleNamespace(command='workflow',json=as_json,no_color=True,workflow='run')
    out=SimpleNamespace(json=lambda value:values.append(value))
    assert cli._dispatch(args,out)==2
    captured=capsys.readouterr()
    if as_json:
        assert values[0]['status']=='not_started' and values[0]['error']['category']=='investigation_compatibility_unverified'
        assert '\x1b' not in json.dumps(values)
    else:
        assert 'Investigation not started' in captured.err and 'Suggested action:' in captured.err
        assert '\nReason:' in captured.err and '\\nReason:' not in captured.err
