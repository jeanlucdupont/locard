"""Presentation projections only; canonical result data must stay intact."""
import copy
import json
from types import SimpleNamespace
import pytest
from forensic_assistant.investigation_ai.presentation import render, proposal_text, limitations
from forensic_assistant.terminal import Palette
from test_investigation_assessment import EID


def result(label='MFT SI Created'):
    return dict(termination='USER_SCOPE_REACHED', findings={'observed':[
        dict(field='/timestamps/0/utc', reported_value='2019-03-15T12:00:00.000000000Z',
             timestamp_semantics=[{'utc':'2019-03-15T12:00:00.000000000Z','type':label}],
             evidence_ids=[EID])]}, state={'investigation_path':[]},
        dry_run_proposal={'tool':'show_evidence','arguments':{'evidence_id':EID},'reason':'Inspect record'},
        metrics={'integrity':{'strategy':'private_sqlite_snapshot','live_case_matches':True}},
        limitations=['Bounded investigation; absence of findings does not prove absence of activity.',
          'Some evidence fields are truncated; inspect the original records',
          'Some exposed fields are truncated; absence is not established',
          'Source metadata contains analyst assertions, not independently verified facts',
          'Dirty hive: transaction logs were not replayed; snapshot may be inconsistent'])


@pytest.mark.parametrize('label', ['MFT SI Created','MFT FN Modified','Registry Key LastWrite','Prefetch LastRun'])
def test_timestamp_semantics_and_concise_dry_run(label):
    value=result(label);before=copy.deepcopy(value)
    text=render(value)
    assert value == before
    assert label + ': 2019-03-15 12:00:00 UTC' in text
    assert 'timestamps / 0 / utc' not in text and EID in text
    assert 'Read-only operations' not in text and 'Completed: 0' not in text
    assert text.count('Dry-run proposal') == text.count('No operation was executed.') == 1
    assert 'Dry-run completed' in text and 'analyst interrupted' not in text
    assert 'Case integrity' not in text and 'Live case matched' not in text
    assert text.count('Some evidence fields were truncated.') == 1
    assert 'Registry hive was dirty; transaction logs were not replayed.' in text and 'Bounded investigation;' not in text
    assert 'Source metadata' not in text
    assert text.count('No supported conclusion was produced.') == 1
    assert 'Reason: Inspect record' in text and 'Model-proposed reason' not in text


def test_unknown_and_mismatched_semantics_fall_back():
    value=result();row=value['findings']['observed'][0]
    row['timestamp_semantics'][0]['utc']='different'
    assert 'timestamps / 0 / utc:' in render(value)
    row['field']='/some_field'
    assert 'some field:' in render(value)
    assert 'MFT SI Created:' not in render(value)


@pytest.mark.parametrize('match', [False,None])
def test_integrity_exceptions_remain_visible(match):
    value=result();value['metrics']['integrity']['live_case_matches']=match
    text=render(value)
    assert 'Warning' in text
    assert ('live case changed' if match is False else 'could not confirm') in text


def test_source_grouping_retains_material_and_unknown_caveats():
    values=['Source metadata includes analyst assertions; these are not independently verified artifact facts',
            'Source metadata contains analyst assertions, not independently verified facts',
            'Source metadata includes analyst assertions; it is not independently verified evidence.',
            'Host context conflicts across sources; cannot correlate.']
    assert limitations(values) == [values[-1]]
    material=limitations(values, source_material=True)
    assert len(material)==2 and 'analyst-supplied' in material[0] and material[1]==values[-1]
    value=result();value['findings']['observed'][0]['source_context']={'conflicts':['hostname']}
    value['limitations'].extend(values)
    assert render(value).count('Source context relies on analyst-supplied')==0


def test_success_has_no_empty_counters_or_boilerplate():
    value=result();value['termination']='ANSWER_SUPPORTED';value['dry_run_proposal']=None;value['limitations']=[]
    text=render(value)
    assert 'Termination' not in text and 'Read-only operations' not in text
    assert 'Limitations' not in text and 'No supported conclusion' not in text


@pytest.mark.parametrize('color,json_mode', [(True,False),(False,False),(True,True)])
def test_dispatch_color_and_json(tmp_path, monkeypatch, capsys, color, json_mode):
    from forensic_assistant.cli import main
    from forensic_assistant.investigation_ai import cli
    from test_interactive_shell import case
    monkeypatch.delenv('NO_COLOR',raising=False)
    monkeypatch.setattr('forensic_assistant.terminal.capable',lambda _:color)
    value=result();before=copy.deepcopy(value)
    monkeypatch.setattr(cli,'dispatch',lambda _:value)
    args=['--db',str(case(tmp_path)),'investigate-ai','--dry-run','Question']
    if json_mode:args.append('--json')
    assert main(args)==0
    text=capsys.readouterr().out
    assert value==before
    if json_mode:
        assert json.loads(text)==value and '\x1b' not in text
        assert 'USER_SCOPE_REACHED' in text and '/timestamps/0/utc' in text
    else:
        assert ('\x1b[' in text)==color
        assert 'Dry-run completed' in text


def test_proposal_styles_and_switches(monkeypatch,capsys):
    from forensic_assistant.investigation_ai.cli import approve
    monkeypatch.delenv('NO_COLOR',raising=False)
    monkeypatch.setattr('forensic_assistant.terminal.capable',lambda _:True)
    monkeypatch.setattr('sys.stdin.isatty',lambda:True)
    def read(prompt,seconds):
        print(prompt);return 'n'
    monkeypatch.setattr('forensic_assistant.interactive.console.timed_line',read)
    for args,colored in [(SimpleNamespace(json=False,no_color=False),True),
                         (SimpleNamespace(json=True,no_color=False),False),
                         (SimpleNamespace(json=False,no_color=True),False)]:
        assert not approve(result()['dry_run_proposal'],1,args=args)
        captured=capsys.readouterr()
        assert not captured.out and ('\x1b[' in captured.err)==colored
        assert '[y/N]' in captured.err and 'Reason:' in captured.err


def test_advanced_command_still_accessible(capsys):
    from forensic_assistant.cli import build_parser
    from forensic_assistant.interactive.help import catalog
    for interactive in (False,True):
        parser=build_parser(interactive=interactive)
        assert 'investigate-ai' not in parser.format_help()
        assert parser.parse_args(['investigate-ai','question']).command=='investigate-ai'
        with pytest.raises(SystemExit) as exc:parser.parse_args(['investigate-ai','--help'])
        assert exc.value.code==0
        assert 'Advanced / Diagnostic' in capsys.readouterr().out
    assert 'investigate-ai' not in catalog(build_parser(interactive=True))
    assert '!' in catalog(build_parser(interactive=True))


def test_source_derived_identity_keeps_assertion_qualification():
    value=result();row=value['findings']['observed'][0]
    row.update(field='/hostname',reported_value='asserted-host',source_context={'hostname':'asserted-host','basis':'analyst-supplied'})
    assert 'analyst-supplied metadata' in render(value)
