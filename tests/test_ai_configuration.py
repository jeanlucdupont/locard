"""AI configuration UX only; synthetic files, no model launch or cloud requests."""
import json
from pathlib import Path
import pytest
from forensic_assistant.ai import cli, settings, runtime
from forensic_assistant.ai.backend import ModelBackend
from forensic_assistant.cli import build_parser
from forensic_assistant.interactive.shell import Shell
from forensic_assistant.interactive.state import State
from test_interactive_shell import Input, case

@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv('LOCALAPPDATA', str(tmp_path/'appdata'))
    for _, variable in settings.PROVIDERS.values():
        if variable: monkeypatch.delenv(variable, raising=False)
    monkeypatch.setattr(runtime.subprocess, 'Popen', lambda *a, **k: pytest.fail('configuration launched a process'))


def files(tmp_path):
    exe=tmp_path/'llama-server.exe';exe.write_bytes(b'synthetic')
    model=tmp_path/'Other model.GGUF';model.write_bytes(b'synthetic')
    return exe,model


def args(*words, read=None):
    value=build_parser().parse_args(['ai',*words])
    if read is not None:value._confirm=read
    return value

@pytest.mark.parametrize('missing', ['both','executable','model_path'])
def test_absent_paths_not_configuration(tmp_path,missing):
    exe,model=files(tmp_path)
    config={**settings.defaults(),'executable':str(exe),'model_path':str(model)}
    for field in ('executable','model_path'):
        if missing in ('both',field):config[field]=''
    assert settings.local_configuration(config)['configuration']=='not_configured'
    if missing=='both':
        assert 'model' not in cli.status(config)
        assert 'Qwen' not in cli.render(cli.status(config))

@pytest.mark.parametrize('field,kind', [('executable','missing'),('model_path','missing'),('executable','directory'),('model_path','directory'),('model_path','extension'),('executable','extension')])
def test_invalid_paths_never_ready(tmp_path,field,kind):
    exe,model=files(tmp_path)
    config={**settings.defaults(),'executable':str(exe),'model_path':str(model)}
    target=tmp_path/('bad.exe' if field=='executable' else 'bad.gguf')
    if kind=='directory':target.mkdir()
    if kind=='extension':target=tmp_path/'bad.txt';target.write_bytes(b'synthetic')
    config[field]=str(target)
    settings.save(config)
    result=cli.status(settings.load())
    assert result['configuration']=='configured_invalid'
    assert result[field]==str(target)
    with pytest.raises(ValueError):ModelBackend().prepare()


def test_valid_paths_status_and_no_independent_model_name(tmp_path):
    exe,model=files(tmp_path)
    result=cli.dispatch(args('configure','--executable',str(exe),'--model-path',str(model)))
    assert result['configuration']=='configured_ready'
    assert result['model']==model.name and result['model_path']==str(model) and result['executable']==str(exe)
    assert settings.load()['model']==''
    with pytest.raises(ValueError,match='cloud'):cli.dispatch(args('configure','--model','wrong-label'))
    assert settings.load()['model']==''


def test_local_wizard_default_minimal_normalized(tmp_path,capsys):
    exe,model=files(tmp_path)
    reader=Input('',str(exe.parent/'folder'/ '..'/exe.name),str(model),ai_setup=True)
    result=cli.dispatch(args('configure',read=reader.read))
    assert result['configuration']=='configured_ready' and result['model']==model.name
    assert result['executable']==str(exe)
    assert reader.prompts==['Provider [1]: ','Path to llama-server.exe: ','Path to GGUF model: ']
    assert 'Model: '+model.name in capsys.readouterr().out


def test_local_retry_and_cancel_preserve_config(tmp_path):
    exe,model=files(tmp_path)
    cli.dispatch(args('configure','--executable',str(exe),'--model-path',str(model)))
    path=settings.root()/'config.json';before=path.read_bytes()
    reader=Input('',str(exe),str(tmp_path/'missing.gguf'),'cancel',ai_setup=True)
    assert cli.dispatch(args('configure',read=reader.read))['status']=='unchanged'
    assert path.read_bytes()==before
    reader=Input('',str(exe),str(tmp_path/'missing.gguf'),'y',str(exe),str(model),ai_setup=True)
    assert cli.dispatch(args('configure',read=reader.read))['configuration']=='configured_ready'

@pytest.mark.parametrize('interruption',[EOFError(),KeyboardInterrupt(),'cancel'])
def test_cancel_before_save_leaves_no_config(interruption):
    reader=Input('',interruption,ai_setup=True)
    assert cli.dispatch(args('configure',read=reader.read))['status']=='unchanged'
    assert not (settings.root()/'config.json').exists()


def test_cloud_disclosure_before_model_and_missing_key(capsys):
    reader=Input('2','y','synthetic',ai_setup=True)
    value=cli.dispatch(args('configure',read=reader.read))
    assert reader.prompts==['Provider [1]: ','Continue? [y/N]: ','Cloud model identifier: ']
    assert value['configuration']=='credential_missing' and value['api_key']=='missing'
    assert 'OPENAI_API_KEY' in value['configuration_detail']
    assert 'may leave this computer' in capsys.readouterr().out


def test_cloud_decline_does_not_ask_model_or_save():
    reader=Input('2','n',ai_setup=True)
    assert cli.dispatch(args('configure',read=reader.read))['status']=='unchanged'
    assert reader.prompts==['Provider [1]: ','Continue? [y/N]: ']
    assert not (settings.root()/'config.json').exists()


def test_cloud_key_availability_without_persistence(monkeypatch,capsys):
    monkeypatch.setenv('OPENAI_API_KEY','synthetic-secret')
    result=cli.dispatch(args('configure',read=Input('2','y','synthetic',ai_setup=True).read))
    assert result['configuration']=='configured_ready'
    assert 'synthetic-secret' not in json.dumps(result)+capsys.readouterr().out+(settings.root()/'config.json').read_text()


def test_status_filters_control_identity(tmp_path,monkeypatch):
    exe,model=files(tmp_path)
    config={**settings.defaults(),'executable':str(exe),'model_path':str(model)}
    monkeypatch.setattr(runtime,'status',lambda:dict(runtime='running',model='different',token='SECRET',instance='SECRET',config_identity='SECRET',endpoint='http://127.0.0.1:8080',runtime_reported_models=['runtime-label']))
    result=cli.status(config)
    assert result['model']==model.name and result['runtime_reported_models']==['runtime-label']
    assert result['runtime']=='running' and 'SECRET' not in json.dumps(result)


def test_shell_skip_once_deterministic_commands_and_no_case_mutation(tmp_path,capsys):
    db=case(tmp_path);before=db.read_bytes()
    reader=Input(str(db),'n','status','case','exit',ai_setup=True)
    assert Shell(State(None),reader,no_color=True).run()==0
    assert sum(p.startswith('Configure AI now?') for p in reader.prompts)==1
    assert '[case' in ''.join(reader.prompts) and db.read_bytes()==before
    assert 'AI is not configured.' in capsys.readouterr().out


def test_shell_default_yes_then_valid_no_repeat(tmp_path):
    db=case(tmp_path);exe,model=files(tmp_path)
    reader=Input(str(db),'','',str(exe),str(model),'exit',ai_setup=True)
    assert Shell(State(None),reader,no_color=True).run()==0
    assert 'Path to GGUF model: ' in reader.prompts
    later=Input(str(db),'exit',ai_setup=True)
    assert Shell(State(None),later,no_color=True).run()==0
    assert not any('Configure AI now?' in p for p in later.prompts)


def test_unconfigured_model_request_has_guidance():
    with pytest.raises(ValueError,match='Use ai configure'):
        ModelBackend().complete([{'role':'user','content':'synthetic'}])



def test_configured_model_request_starts_once_and_reuses(tmp_path,monkeypatch):
    exe,model=files(tmp_path)
    client=ModelBackend(config={**settings.defaults(),'executable':str(exe),'model_path':str(model)})
    starts=[]
    monkeypatch.setattr(runtime,'ensure',lambda config,phase: starts.append(config) or {'synthetic':'owner'})
    monkeypatch.setattr(runtime,'request',lambda *a,**k:{'endpoint':'http://127.0.0.1:8080'})
    client.prepare();client.prepare()
    assert len(starts)==1 and starts[0]['model_path']==str(model)
    assert client.model_name==model.name and client.endpoint=='http://127.0.0.1:8080'


def test_invalid_script_configuration_preserves_previous(tmp_path):
    exe,model=files(tmp_path)
    cli.dispatch(args('configure','--executable',str(exe),'--model-path',str(model)))
    path=settings.root()/'config.json';before=path.read_bytes()
    with pytest.raises(ValueError):
        cli.dispatch(args('configure','--model-path',str(tmp_path/'missing.gguf')))
    assert path.read_bytes()==before


def test_invalid_startup_can_be_skipped_and_cloud_ready_does_not_prompt(tmp_path,monkeypatch,capsys):
    config={**settings.defaults(),'executable':str(tmp_path/'missing.exe'),'model_path':str(tmp_path/'missing.gguf')}
    settings.save(config)
    reader=Input('n',ai_setup=True)
    cli.offer_setup(reader.read)
    assert reader.prompts==['Configure AI now? [Y/n]: ']
    assert 'invalid' in capsys.readouterr().out
    settings.save({**config,'provider':'openai','model':'synthetic','cloud_acknowledged':True})
    monkeypatch.setenv('OPENAI_API_KEY','synthetic-secret')
    cli.offer_setup(lambda p:pytest.fail('ready configuration prompted'))
