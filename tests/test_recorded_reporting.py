"""Synthetic recorded histories only; no case access or provider dispatch."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sqlite3

import pytest

from forensic_assistant.reporting import recorded as r, recorded_model as m
from forensic_assistant.reporting.model import canonical, digest
from forensic_assistant.investigation_ai import findings as f, d2
from test_explanation_live import execute
from test_explanation_replay_status import empty_run
from test_findings import register, refs, prepared, answer
from forensic_assistant.investigation_ai import d2_wire as wire


@pytest.fixture(scope='module')
def source(tmp_path_factory):
    root = tmp_path_factory.mktemp('report-history')
    result, _, _, _ = execute(root)
    return root/'runs', result['investigation_id'], d2.open_history(root/'runs', result['investigation_id'])


@pytest.fixture(autouse=True)
def no_provider(monkeypatch):
    def forbidden(*a, **kw):
        pytest.fail('provider/legacy case reporting entered')
    monkeypatch.setattr('forensic_assistant.ai.backend.ModelBackend.complete', forbidden)
    monkeypatch.setattr('forensic_assistant.reporting.collect.build', forbidden)
    monkeypatch.setattr('forensic_assistant.reporting.bundle.generate', forbidden)


@pytest.fixture(scope='module')
def projection(source):
    return r.build(source[0], source[1])


def test_history_only(projection):
    assert projection['content']['workspace'] is None
    assert projection['content']['supports']
    assert projection['content']['original_assessment']
    assert r.validate_projection(projection) == projection
    html = r.render_html(projection).decode()
    assert 'No attached analyst-reviewed' in html and 'No accepted findings' in html
    assert 'Content-Security-Policy' in html and '<script' not in html


@pytest.mark.parametrize('kind', m.TYPES)
def test_views(source, kind):
    result = r.build(source[0], source[1], report_type=kind)
    assert ('Locard '+kind+' report').encode() in r.render_html(result)


def test_zero_analysis(tmp_path):
    result = empty_run(tmp_path, 'structure')
    p = r.build(tmp_path/'runs', result['investigation_id'])
    assert p['content']['view'] and p['content']['factual']['clauses'] == []
    assert b'No accepted factual clauses' in r.render_html(p)


def test_empty_workspace(tmp_path, source):
    w = f.create(tmp_path/'review.findings', source[0], source[1], actor='Synthetic')
    before = w.path.read_bytes()
    p = r.build(source[0], source[1], workspace=w.directory)
    assert p['content']['workspace']['revision'] == 0
    assert b'No accepted findings' in r.render_html(p)
    assert w.path.read_bytes() == before


def test_findings_all_states_and_ai(tmp_path, source):
    w = f.create(tmp_path/'review.findings', source[0], source[1], actor='Synthetic')
    old = register(w, source)
    w.review(old, 'accept', actor='Analyst', expected_revision=1)
    replacement = w.supersede(old, actor='Analyst', expected_revision=2, rationale='Narrower.',
        statement='Replacement proposal.', supporting_ids=refs(source)[:1])
    rejected = register(w, source, 3)
    w.review(rejected, 'reject', actor='Analyst', expected_revision=4)
    p = prepared(source)
    ai = w.import_d2(p, wire.J(answer(p)), 0, actor='Analyst', expected_revision=5)
    w.review(ai, 'accept', actor='Analyst', expected_revision=6)
    before = w.path.read_bytes()
    executive = r.build(source[0], source[1], workspace=w.directory, report_type='executive')
    content = executive['content']
    assert content['original_assessment'] == source[2]._original
    rows = {v['id']: v for v in content['workspace']['findings']}
    assert rows[old]['state'] == 'superseded' and rows[replacement]['state'] == 'proposed'
    assert rows[rejected]['state'] == 'rejected' and rows[ai]['candidate']['origin'] == 'ai_proposal'
    assert rows[ai]['candidate']['contrary']
    html = r.render_html(executive).decode()
    assert 'unverified AI proposal' in html and 'unexecuted' in html and 'Clock agreement' in html
    titles = [b['title'] for b in r.render_view(executive)]
    assert not any('Historical inactive' in t for t in titles)
    handover = r.build(source[0], source[1], workspace=w.directory, report_type='handover')
    assert 'Historical inactive finding' in r.render_html(handover).decode()
    assert before == w.path.read_bytes()


def test_determinism(source, projection):
    second = r.build(source[0], source[1], generation=projection['generation'])
    assert projection == second
    assert r.render_html(projection) == r.render_html(second)
    later = deepcopy(projection)
    later['generation']['generated_utc'] = '2030-01-01T00:00:00+00:00'
    assert later['content_digest'] == projection['content_digest']
    assert r.render_html(later) != r.render_html(projection)


def test_publish_inspect_revalidate(tmp_path, source):
    out = tmp_path/'bundle'
    r.publish(source[0], source[1], out)
    assert r.inspect(out)['source_binding'] == 'NOT_CHECKED'
    assert r.revalidate(out, source[0], source[1])['evidence_grounding'] == 'PASS'
    with pytest.raises(ValueError, match='DESTINATION_EXISTS'):
        r.publish(source[0], source[1], out)


def reseal(p):
    p['content_digest'] = digest(p['content'])
    return p


@pytest.mark.parametrize('mutation', ['version', 'extra', 'missing_support', 'view', 's3', 'qualifications', 'field', 'lineage', 'interpretation'])
def test_projection_rejects_changes(projection, mutation):
    p = deepcopy(projection)
    c = p['content']
    if mutation == 'version': p['contract'] = 'unknown'
    elif mutation == 'extra': c['new_authority'] = True
    elif mutation == 'missing_support': c['supports'].pop(next(iter(c['supports'])))
    elif mutation == 'view': c['view'] = {}
    elif mutation == 's3': c['original_assessment']['status'] = 'SUPPORTED_WITHIN_SCOPE'
    elif mutation == 'qualifications': next(iter(c['units'].values()))['qualifications'].append('Invented')
    elif mutation == 'interpretation':
        next(u for u in c['units'].values() if u['interpretations'])['interpretations'] = []
    else:
        ref = next(iter(c['supports']))
        if mutation == 'field': c['supports'][ref]['field']['value'] = 'Invented'
        else: c['supports'][ref]['lineage'] = {}
    with pytest.raises((ValueError, KeyError)):
        r.validate_projection(reseal(p))


@pytest.mark.parametrize('limit,value', [('MAX_PROJECTION', 100), ('MAX_NODES', 10), ('MAX_TEXT', 5), ('MAX_SUPPORTS', 1), ('MAX_HTML', 100), ('MAX_BLOCKS', 2), ('MAX_BUNDLE', 100)])
def test_resource_bounds(projection, monkeypatch, limit, value):
    monkeypatch.setattr(m, limit, value)
    with pytest.raises(ValueError, match='LIMIT'):
        r._payloads(projection)


def test_html_injection_and_original_fields(tmp_path, source):
    w = f.create(tmp_path/'review.findings', source[0], source[1], actor='Synthetic')
    attack = '<script src="https://bad.invalid/x">alert(1)</script> " onmouseover="x" javascript:evil file:///secret **bold** 漢字'
    fid = w.register(actor='Analyst', expected_revision=0, kind='analyst_hypothesis',
        statement=attack, supporting_ids=refs(source)[:1], explanation=attack, limitations=[attack])
    w.review(fid, 'accept', actor='Analyst', expected_revision=1)
    p = r.build(source[0], source[1], workspace=w.directory)
    html = r.render_html(p).decode()
    assert '<script' not in html and '<img ' not in html
    import re
    assert all(target.startswith('#') for target in re.findall(r'href="([^"]*)"', html))
    assert '&lt;script' in html and '&quot;' in html and '漢字' in html
    assert 'src="https' not in html
    for leaf in p['content']['supports'].values():
        assert leaf['source']['provenance'] and leaf['lineage']
        assert leaf['field']['pointer']
    assert 'display_clipping' in html and 'Original support' in html


def test_missing_original_support(source, monkeypatch):
    monkeypatch.setattr(r.Source, 'restore', lambda self: {})
    with pytest.raises(ValueError, match='UNIT_CLOSURE'):
        r.build(source[0], source[1])


def test_unavailable_source(tmp_path):
    with pytest.raises((OSError, ValueError)):
        r.build(tmp_path/'missing', '0'*32)


@pytest.mark.parametrize('part', ['manifest.json', 'events.jsonl'])
def test_corrupt_transcript(tmp_path, source, part):
    import shutil
    root = tmp_path/'copy'
    shutil.copytree(source[0], root)
    path = root/source[1]/part
    raw = path.read_bytes()
    path.write_bytes(raw+b'broken')
    with pytest.raises((ValueError, OSError)):
        r.build(root, source[1])


def test_workspace_binding_failure(tmp_path, source):
    w = f.create(tmp_path/'review.findings', source[0], source[1], actor='Synthetic')
    # Only disposable test storage is changed.
    with sqlite3.connect(w.path) as conn:
        metadata = json.loads(conn.execute('select value from metadata').fetchone()[0])
        metadata['binding']['source']['manifest_sha256'] = '0'*64
        conn.execute('update metadata set value=?', (json.dumps(metadata),))
    with pytest.raises(ValueError, match='WORKSPACE_BINDING'):
        r.build(source[0], source[1], workspace=w.directory)


@pytest.mark.parametrize('name', ['../escape', 'inside.findings/bundle', 'inside.investigations/bundle', 'NUL', 'original/bundle'])
def test_unsafe_destinations(tmp_path, name):
    (tmp_path/'inside.findings').mkdir()
    (tmp_path/'inside.investigations').mkdir()
    (tmp_path/'original').mkdir()
    with pytest.raises(ValueError):
        r._destination(tmp_path/name, [tmp_path/'original'])


def test_input_container_destination(source):
    with pytest.raises(ValueError, match='PROTECTED'):
        r.publish(source[0], source[1], source[0]/'new-report')


@pytest.mark.parametrize('failure', ['write', 'rename', 'cancel'])
def test_failed_publication_leaves_no_bundle(tmp_path, source, monkeypatch, failure):
    def fail(*args):
        if failure == 'cancel': raise KeyboardInterrupt()
        raise OSError('synthetic failure')
    monkeypatch.setattr(r, '_rename_new' if failure == 'rename' else '_write', fail)
    out = tmp_path/'bundle'
    with pytest.raises((OSError, KeyboardInterrupt)):
        r.publish(source[0], source[1], out)
    assert not out.exists()
    assert not list(tmp_path.glob('.locard-recorded-report-*'))


def test_complete_write_detects_short_write(tmp_path, monkeypatch):
    class Short:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def write(self, data): return len(data)-1
    monkeypatch.setattr(Path, 'open', lambda *args, **kwargs: Short())
    with pytest.raises(OSError, match='SHORT_WRITE'):
        r._write(tmp_path/'file', b'payload')


def test_source_mutation_blocks_publication(tmp_path, source, monkeypatch):
    import shutil
    root = tmp_path/'copy'
    shutil.copytree(source[0], root)
    original = r.render_html
    def change(p):
        html = original(p)
        path = root/source[1]/'manifest.json'
        path.write_bytes(path.read_bytes()+b'broken')
        return html
    monkeypatch.setattr(r, 'render_html', change)
    with pytest.raises(ValueError):
        r.publish(root, source[1], tmp_path/'bundle')
    assert not (tmp_path/'bundle').exists()


def test_workspace_revision_blocks_publication(tmp_path, source, monkeypatch):
    w = f.create(tmp_path/'review.findings', source[0], source[1], actor='Synthetic')
    original = r.render_html
    changed = False
    def change(p):
        nonlocal changed
        html = original(p)
        if not changed:
            register(w, source)
            changed = True
        return html
    monkeypatch.setattr(r, 'render_html', change)
    with pytest.raises(ValueError, match='WORKSPACE_CHANGED'):
        r.publish(source[0], source[1], tmp_path/'bundle', workspace=w.directory)
    assert not (tmp_path/'bundle').exists()


def test_decision_digest_and_later_revision(tmp_path, source):
    w = f.create(tmp_path/'review.findings', source[0], source[1], actor='Synthetic')
    fid = register(w, source)
    before = r.build(source[0], source[1], workspace=w.directory)
    out = tmp_path/'bundle'
    r.publish(source[0], source[1], out, workspace=w.directory)
    w.review(fid, 'accept', actor='Analyst', expected_revision=1)
    after = r.build(source[0], source[1], workspace=w.directory)
    assert before['content_digest'] != after['content_digest']
    with pytest.raises(ValueError, match='SOURCE_OR_REVISION_CHANGED'):
        r.revalidate(out, source[0], source[1], workspace=w.directory)


def test_policy_digest(projection):
    p = deepcopy(projection)
    p['content']['policy']['redaction'] = 'identifiers'
    assert digest(p['content']) != projection['content_digest']
    with pytest.raises(ValueError, match='POLICY'):
        r.validate_projection(reseal(p))  # Unsupported policies fail, not silently applied.


def test_bundle_corruption_and_duplicate_keys(tmp_path, source):
    from forensic_assistant.reporting.model import loads
    with pytest.raises(ValueError, match='Duplicate'):
        loads('{"contract":"x","contract":"y"}')
    out = tmp_path/'bundle'
    r.publish(source[0], source[1], out)
    (out/'report.html').write_bytes(b'<script>alert(1)</script>')
    with pytest.raises(ValueError, match='FILE_DIGEST'):
        r.inspect(out)


def test_no_case_or_source_writes(tmp_path, source, monkeypatch):
    root = source[0]/source[1]
    before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in root.iterdir() if p.is_file()}
    def forbidden(*a, **kw): raise AssertionError('live case connection')
    monkeypatch.setattr(sqlite3, 'connect', forbidden)
    p = r.build(source[0], source[1])
    assert p['content']['supports']
    r.publish(source[0], source[1], tmp_path/'bundle')
    assert before == {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in root.iterdir() if p.is_file()}


def test_cli_bypasses_case_activity(tmp_path, source, monkeypatch, capsys):
    from forensic_assistant import cli, activity
    def forbidden(*a, **kw): raise AssertionError('case/activity path')
    monkeypatch.setattr(activity.Command, '__enter__', forbidden)
    monkeypatch.setattr(sqlite3, 'connect', forbidden)
    args = cli.build_parser().parse_args(['report', 'recorded', '--transcript-root', str(source[0]),
        '--run', source[1], '--output', str(tmp_path/'bundle'), '--profile', 'executive'])
    assert cli.dispatch(args) == 0
    assert 'PUBLISHED' in capsys.readouterr().out


def test_legacy_import_restriction(source):
    from forensic_assistant.reporting.transcripts import load
    with pytest.raises(ValueError, match='Incremental report import'):
        load(source[0], source[1])


def test_d1_all_pages_and_omissions(projection):
    pages = projection['content']['explanation_pages']
    assert pages and pages[-1]['next_cursor'] is None and pages[-1]['assembly_exhausted']
    html = r.render_html(projection).decode()
    for index, page in enumerate(pages, 1):
        assert 'Explanation page '+str(index) in html
        assert 'assembly_limit_omitted' in html and 'source_organization_incomplete' in html
        for s in page['statements']:
            assert s['qualifications'] is not None


@pytest.mark.parametrize('error', [ValueError, OSError, sqlite3.DatabaseError])
def test_source_safe_errors(monkeypatch, capsys, error):
    from argparse import Namespace
    def fail(*a, **kw): raise error('Secret evidence text / private/path')
    monkeypatch.setattr(r, 'dispatch', fail)
    assert r.cli(Namespace()) == 2
    assert 'Secret' not in capsys.readouterr().out


def test_unknown_workspace_schema(tmp_path, source):
    w = f.create(tmp_path/'review.findings', source[0], source[1], actor='Synthetic')
    with sqlite3.connect(w.path) as conn:
        conn.execute('create table forged(value)')
    with pytest.raises(ValueError, match='SCHEMA'):
        r.build(source[0], source[1], workspace=w.directory)


def test_truncation_and_timestamp_semantics(projection):
    # Exercise presentation with a validated synthetic S1 fixture, rather than
    # editing an original transcript or relaxing its support checks.
    from test_synthesis_packets import context
    from test_compact_disclosure import records
    from forensic_assistant.investigation_ai import packets, question_assessment
    import time
    rows = deepcopy(records())
    for row in rows:
        row.setdefault('coverage_notes', []).append('Synthetic clock timezone unknown; no physical ordering established.')
        row.setdefault('truncated_fields', []).append('synthetic_original_field')
    ctx = context(rows)
    meter = packets.Meter(packets.Limits(), time.monotonic)
    restored = {c['id']: packets._rehydrate(c, ctx, meter) for c in ctx.factual['clauses']}
    assert all(restored.values())
    p = deepcopy(projection)
    c = p['content']
    c.update(factual=ctx.factual, related=ctx.related, view=ctx.factual['evidence_state'],
             organization=None, explanation_pages=[], workspace=None)
    c['original_assessment'] = question_assessment._assess(c['question'], c['source']['run_id'], ctx.related)
    c['supports'], c['units'] = m.support_map(restored, c['view'])
    html = r.render_html(reseal(p)).decode()
    assert 'synthetic_original_field' in html and 'timezone unknown' in html
    assert 'display_clipping' in html and 'false' in html
    for leaf in c['supports'].values():
        assert leaf['source']['context']['truncated_fields']
    assert 'do not establish' in html or 'does not establish' in html


def test_publication_race_never_overwrites(tmp_path, source, monkeypatch):
    original = r._rename_new
    def race(stage, dest):
        dest.mkdir()
        (dest/'sentinel').write_text('retain')
        original(stage, dest)
    monkeypatch.setattr(r, '_rename_new', race)
    out = tmp_path/'bundle'
    with pytest.raises(OSError, match='PUBLICATION_UNCERTAIN'):
        r.publish(source[0], source[1], out)
    assert (out/'sentinel').read_text() == 'retain'
    assert set(p.name for p in out.iterdir()) == {'sentinel'}


def test_projection_unknown_nested_key(projection):
    p = deepcopy(projection)
    p['content']['explanation_pages'][0]['certified_truth'] = True
    with pytest.raises(ValueError, match='SHAPE'):
        r.validate_projection(reseal(p))


def test_cleanup_uncertainty(tmp_path, source, monkeypatch):
    def fail(*args): raise OSError('synthetic storage fault')
    monkeypatch.setattr(r, '_write', fail)
    monkeypatch.setattr(r.shutil, 'rmtree', fail)
    with pytest.raises(OSError, match='CLEANUP_UNCONFIRMED'):
        r.publish(source[0], source[1], tmp_path/'bundle')
    assert not (tmp_path/'bundle').exists()


def test_uncertain_rename_does_not_delete_public_output(tmp_path, source, monkeypatch):
    original = r._rename_new
    def uncertain(stage, dest):
        original(stage, dest)
        raise OSError('confirmation failed')
    monkeypatch.setattr(r, '_rename_new', uncertain)
    out = tmp_path/'bundle'
    with pytest.raises(OSError, match='PUBLICATION_UNCERTAIN'):
        r.publish(source[0], source[1], out)
    assert r.inspect(out)['file_integrity'] == 'PASS'


def test_synthetic_performance(tmp_path, source):
    """Measured Python allocation peak, not process RSS or an enforced deadline."""
    import time
    import tracemalloc
    from forensic_assistant.investigation_ai.transcript import digest as event_digest
    results = []
    for name, count, large in [('small', 0, False), ('moderate', 24, False), ('near_limit', 1024, True)]:
        w = f.create(tmp_path/(name+'.findings'), source[0], source[1], actor='Synthetic')
        candidate = f._manual(source[2], 'analyst_hypothesis', 'Synthetic reviewed context.', refs(source)[:1], [],
            explanation='X'*4000 if large else '', limitations=['Qualification '+str(i)+' '+('Q'*1980) for i in range(32)] if large else [])
        with w._connection(True) as conn:
            metadata, _ = w._load(conn)
            head = event_digest(metadata)
            total = 0
            for i in range(count):
                e = dict(contract=f.CONTRACT, workspace_id=metadata['id'], sequence=i+1, previous=head,
                    timestamp='2026-11-13T00:00:00+00:00', actor='Synthetic', action='propose',
                    finding_id=format(i+1, '032x'), payload=dict(candidate=candidate))
                raw = canonical(e).decode()
                if total+len(raw.encode()) > int(f.MAX_TOTAL*.97): break
                head = event_digest(e)
                conn.execute('insert into events(sequence,body,hash) values(?,?,?)', (i+1, raw, head))
                total += len(raw.encode())
        start = time.perf_counter()
        tracemalloc.start()
        status = 'generated'
        sizes = {}
        try:
            p = r.build(source[0], source[1], workspace=w.directory)
            payloads = r._payloads(p)
            sizes = {key: len(value) for key, value in payloads.items()}
        except ValueError as exc:
            assert name == 'near_limit' and 'LIMIT' in str(exc)
            status = str(exc)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        results.append(dict(case=name, input_event_bytes=total, seconds=round(time.perf_counter()-start, 3),
                            python_peak_bytes=peak, status=status, output_bytes=sizes))
    assert results[0]['status'] == results[1]['status'] == 'generated'
    assert results[2]['input_event_bytes'] > f.MAX_TOTAL*.95
    print('RECORDED_REPORT_BENCHMARK '+json.dumps(results))
