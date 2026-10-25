"""Temporary, explicitly armed guided MFT acceptance timeout."""
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from forensic_assistant import activity, v2_cli
from forensic_assistant.database.db import connect
from forensic_assistant.interactive import setup, discovery
from forensic_assistant.terminal import Palette

ENV = 'LOCARD_GUIDED_MFT_PARSER_TIMEOUT'


@pytest.mark.parametrize('override', [None, '3600'])
@pytest.mark.parametrize('cancel', [False, True])
def test_guided_override_is_mft_only_and_one_shot(tmp_path, monkeypatch, override, cancel):
    monkeypatch.delenv(ENV, raising=False)
    if override:
        monkeypatch.setenv(ENV, override)
    target = tmp_path / 'case.db'
    connect(target).close()
    items = [discovery.Candidate(tmp_path / kind, kind) for kind in ('mft','registry','prefetch','evtx','browser')]
    plan = setup.Plan('Synthetic', '', '', target, items=items,
                      browsers=[(items[-1].path, 'chrome', 'Default')])
    monkeypatch.setattr(discovery, 'candidate_path', lambda item: str(item.path))
    seen = []
    def ingest(db, args, callback):
        kind = args.command.removeprefix('ingest-')
        seen.append((kind, args.parser_timeout))
        if cancel and len(seen) == 1:
            raise KeyboardInterrupt
        result = dict(status='complete', inserted=1, duplicates=0, errors=0)
        callback(args.path, kind, result)
        return [result]
    monkeypatch.setattr(v2_cli, 'ingest_sources', ingest)
    session = activity.Session(target)
    try:
        with activity.bind(session):
            if cancel:
                with pytest.raises(KeyboardInterrupt):
                    setup.execute(plan, session, Palette())
            else:
                setup.execute(plan, session, Palette())
                assert dict(seen) == {kind: 3600 if kind == 'mft' and override else 300 for kind in discovery.CATEGORIES}
            assert ENV not in os.environ
            assert seen[0] == ('mft', 3600 if override else 300)
            seen.append(('separator', 0))  # Avoid the injected first-call cancellation.
            setup.execute(plan, session, Palette())
            assert all(timeout == 300 for kind, timeout in seen[seen.index(('separator',0))+1:])
    finally:
        session.end()


@pytest.mark.parametrize('value', ['', '0', '3601', 'forever'])
def test_invalid_override_fails_before_source_changes(tmp_path, monkeypatch, value):
    monkeypatch.setenv(ENV, value)
    target=tmp_path/'case.db'
    connect(target).close()
    before=target.read_bytes()
    with pytest.raises(ValueError, match='must be 3600 or unset'):
        setup.execute(setup.Plan('Synthetic','','',target), None, Palette())
    assert target.read_bytes() == before
    assert ENV not in os.environ


def test_extended_timeout_does_not_disable_stage_cap(tmp_path, monkeypatch):
    from forensic_assistant.artifacts import ingest
    import io
    stage = tmp_path/'stage.db'
    stage.write_bytes(b'')
    original_stat = Path.stat
    monkeypatch.setattr(Path, 'stat', lambda p, *a, **kw: SimpleNamespace(st_size=8*1024**3+1) if p == stage else original_stat(p,*a,**kw))
    processes=[]
    class Process:
        pid=999_999_999
        returncode=None
        def __init__(self,*a,**kw):
            self.stdin=io.BytesIO();self.killed=False;processes.append(self)
        def poll(self):return self.returncode
        def kill(self):self.killed=True;self.returncode=-1
        def wait(self,**kw):self.returncode=-1;return -1
    monkeypatch.setattr(ingest.subprocess,'Popen',Process)
    with pytest.raises(ValueError,match='exceeds 8 GiB'):
        ingest.worker('mft','unused','a'*64,stage,{},3600)
    assert processes[0].poll() is not None  # Cooperative startup exit is valid cleanup.
    assert processes[0].stdin.closed
