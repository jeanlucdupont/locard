"""End-to-end browser ingestion, provenance and normalized queries."""
from contextlib import closing
import json
from forensic_assistant.database.db import connect
from forensic_assistant.cli import build_parser
from forensic_assistant import v2_cli
from forensic_assistant.retrieval.evidence import EvidenceQueries, get_evidence
from forensic_assistant.artifacts.worker import run
from forensic_assistant.database import sources
from test_browser_parser import history


def ingest(db, path, product='chrome', profile='Default', host='host-a', source=None):
    options = ['ingest-browser', str(path), '--browser', product, '--profile', profile]
    options += ['--source', source] if source else ['--hostname', host, '--user', product + '-user']
    return v2_cli.ingest_sources(db, build_parser().parse_args(options))[0]


def test_browser_ingestion_context_isolation_duplicates_and_queries(tmp_path):
    path = tmp_path / 'History'
    history(path).close()
    with closing(connect(tmp_path / 'case.db')) as db:
        first = ingest(db, path)
        assert first['status'] == 'complete', list(db.execute('SELECT message FROM ingestion_errors'))
        assert first['inserted'] == 2
        chrome = EvidenceQueries(db).search(artifact='browser', browser='chrome').records
        sid = chrome[0]['context']['source_ids'][0]
        second = ingest(db, path, source=sid)
        assert second['inserted'] == 0 and second['duplicates'] == 2
        edge_result = ingest(db, path, 'edge', 'Profile 1', 'host-b')
        assert edge_result['inserted'] == 2
        edge = EvidenceQueries(db).search(artifact='browser', browser='edge').records
        assert {r['id'] for r in chrome}.isdisjoint(r['id'] for r in edge)
        for product, host, profile in [('chrome', 'host-a', 'Default'), ('edge', 'host-b', 'Profile 1')]:
            records = EvidenceQueries(db).search(artifact='browser', hostname=host, username=product+'-user', profile=profile).records
            assert len(records) == 2
            for record in records:
                assert record['host_key'] == host
                assert record['detail']['browser_product'] == product
                assert record['detail']['profile'] == profile
                assert len(record['context']['source_ids']) == 1
                occurrences = record['context']['browser_occurrences']
                assert len(occurrences) == (2 if product == 'chrome' else 1)
                assert all(o['source_file'] == str(path.resolve()) for o in occurrences)
                assert sources.summary(db, record['context']['source_ids'][0])['evidence_count'] == 2
        q = EvidenceQueries(db)
        assert q.search(source_id=sid).total == 2
        assert q.search(url='https://example.com/tool.exe').total == 4
        assert q.search(url_contains='/redirect').total == 2
        assert q.search(title='Example').total == 2
        assert q.search(download_path=r'c:\users\alice\downloads\TOOL.EXE').total == 2
        assert q.search(download_path_contains='tool.exe').total == 2
        assert q.search(url_contains='%').total == 0
        assert q.search(timeline=True).total == 6
        assert not db.execute('PRAGMA foreign_key_check').fetchone()
        assert db.execute('SELECT count(*) FROM source_contexts').fetchone()[0] == 0


def test_browser_requires_explicit_upgrade_before_source_creation(tmp_path):
    import pytest
    from test_browser_schema import schema4
    case = tmp_path / 'old.db'
    schema4(case)
    path = tmp_path / 'History'
    history(path).close()
    with closing(connect(case)) as db:
        with pytest.raises(ValueError, match='explicitly'):
            ingest(db, path)
        assert db.execute('PRAGMA user_version').fetchone()[0] == 4
        assert db.execute('SELECT count(*) FROM sources').fetchone()[0] == 0
from test_mixed_temporal import mixed_case


def test_browser_human_commands_and_mixed_host_window(mixed_case, tmp_path):
    from test_mixed_temporal import BASE_FT, PF_TIME, UA_SLOT
    from forensic_assistant.retrieval import show_display, search_display, around_display
    from forensic_assistant.retrieval.analysis_display import render_investigation
    from forensic_assistant.correlation.investigation import investigate
    from forensic_assistant.terminal import Palette, SGR
    from forensic_assistant.retrieval.status_display import render as status_render, context
    db, pfid, uaid, sids = mixed_case
    path = tmp_path / 'History'
    with closing(history(path)) as original:
        with original:
            original.execute('UPDATE downloads SET target_path=?,start_time=?,end_time=?',
                             (r'C:\Users\alice\Downloads\test.exe', BASE_FT//10-2000000, BASE_FT//10-1000000))
            original.execute('UPDATE visits SET visit_time=?', (BASE_FT//10-3000000,))
    assert ingest(db, path)['status'] == 'complete'
    assert ingest(db, path, 'edge', 'Profile 1', 'host-b')['status'] == 'complete'
    q = EvidenceQueries(db)
    download = q.search(browser='chrome', download_path_contains='test.exe').records[0]
    before = list(db.iterdump())
    for color in (False, True):
        shown = show_display.render(download, Palette(color))
        assert 'BrowserDownload' in shown and r'C:\Users\alice\Downloads\test.exe' in shown
        assert 'does not prove execution' in SGR.sub('', shown)
        search_args = build_parser().parse_args(['search', '--artifact', 'browser', '--browser', 'chrome', '--url-contains', 'example.com'])
        result, code = v2_cli.dispatch(db, search_args)
        assert code == 0 and result['total'] == 2
        shown = search_display.render(result, Palette(color), width=160)
        assert 'BrowserVisit' in shown and 'BrowserDownload' in shown and download['id'] not in shown
        args = build_parser().parse_args(['around', download['id'], '--timestamp-slot', 'Browser.DownloadStart', '--text', '--seconds', '5'])
        result, code = v2_cli.dispatch(db, args)
        assert {r['id'] for r in result['records']} >= {pfid, uaid, download['id']}
        assert all(r['host_key'] == 'host-a' for r in result['records'])
        rendered = around_display.render(result, download, v2_cli.anchor_time(download, 'Browser.DownloadStart'), args, palette=Palette(color))
        assert 'BrowserDownload' in rendered and 'Prefetch' in rendered and 'UserAssist' in rendered
        inv = investigate(db, download['id'], seconds=5, timestamp_slot='Browser.DownloadStart')
        shown = render_investigation(inv, Palette(color))
        assert 'Investigation summary' in shown and 'basename' in shown
        assert 'does not prove' in shown and 'causality' in shown
        timeline_args = build_parser().parse_args(['timeline', '--start', '2020-01-01T09:59:55Z', '--end', '2020-01-01T10:00:05Z', '--text'])
        output, code = v2_cli.dispatch(db, timeline_args)
        assert code == 0 and 'BrowserDownload' in v2_cli.render(output, methodology=False, palette=Palette(color))
    result, code = v2_cli.dispatch(db, build_parser().parse_args(['status']))
    assert result['browser_counts'] == {'browser_download': 2, 'browser_visit': 2}
    shown = status_render(result, 'synthetic.db', context(db))
    assert 'Browser: 4' in shown and 'Visits: 2' in shown and 'Downloads: 2' in shown
    assert before == list(db.iterdump())


def test_summary_excludes_unrelated_visits():
    from test_investigation_summary import record, result, chosen, text, stamp
    def browser_record(index, url, download=False):
        row = record('browser', '', index, 1_000_000_000)
        row['artifact_type'] = 'browser_download' if download else 'browser_visit'
        row['timestamps'][0]['slot'] = 'Browser.DownloadStart' if download else 'Browser.VisitTime'
        row['detail'] = dict(url=url, target_path=r'C:\Downloads\tool.exe' if download else None,
                             state_name='complete', url_chain=[])
        return row
    anchor = record('prefetch', 'TOOL.EXE', 'anchor', 2_000_000_000)
    download = browser_record('download', 'https://example.com/tool.exe', True)
    visit = browser_record('visit', 'https://example.com/tool.exe')
    noise = [browser_record('noise'+str(i), 'https://example.com/noise/'+str(i)) for i in range(40)]
    output = result(anchor, download, visit, *noise)
    selected, count = chosen(output)
    assert {o.record['id'] for o in selected} == {download['id'], visit['id']}
    assert count == 2 and len(output['evidence_records']) == 43
    shown = text(output)
    assert 'Browser recorded download' in shown and 'Browser recorded visit' in shown
    assert 'noise' not in shown and 'binary identity' in shown


def test_browser_completion_is_parser_derived():
    from forensic_assistant.interactive.completion import complete
    text = 'ingest-browser --'
    options = complete(text, len(text)).candidates
    assert {'--browser', '--profile', '--source', '--hostname', '--user'} <= set(options)
    text = 'search --'
    options = complete(text, len(text)).candidates
    assert {'--url', '--url-contains', '--title', '--title-contains', '--download-path', '--download-path-contains', '--browser', '--profile'} <= set(options)
