"""Explicit analyst review of recorded findings. No provider or evidence DB access.

The SQLite file is derived local application state, not a source of evidence authority.
All mutations use an expected workspace revision and an append-only transaction.
"""
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timezone
import argparse
import os
from pathlib import Path
import re
import sqlite3
import time
import uuid

from . import d2, packets as b1
from .storage import local_path, DirectoryGuard
from .transcript import digest
from .state import encoded
from .contracts import loads

CONTRACT = 'analyst-findings-workspace-v1'
FINDING = 'analyst-finding-v1'
APP_ID = 0x4C464E44
MAX_EVENT = 262144
MAX_EVENTS = 1024
MAX_TOTAL = 32 * 1024 * 1024
KINDS = ('original_observation', 'deterministic_interpretation', 'deterministic_relationship',
         'ai_proposal', 'analyst_hypothesis', 'analyst_reviewed_conclusion')


def _text(value, limit=4096, empty=False):
    if (type(value) is not str or len(value.encode('utf-8')) > limit or
            (not empty and not value.strip()) or any(ord(c) < 32 and c not in '\n\t' for c in value)):
        raise ValueError('FINDINGS_INVALID_TEXT')
    return value


def _id(value):
    if type(value) is not str or not re.fullmatch('[a-f0-9]{32}', value):
        raise ValueError('FINDINGS_INVALID_ID')
    return value


def _stamp():
    return datetime.now(timezone.utc).isoformat()


def _keys(value, keys):
    if type(value) is not dict or set(value) != set(keys.split()):
        raise ValueError('FINDINGS_RECORD_SHAPE')


def _refs(values):
    if type(values) is not list or len(values) > 32 or len(set(values)) != len(values):
        raise ValueError('FINDINGS_REFERENCE_LIST')
    for v in values:
        if type(v) is not str or not re.fullmatch('[a-f0-9]{64}', v):
            raise ValueError('FINDINGS_ORIGINAL_REFERENCE_REQUIRED')
    return values


def _binding(history):
    history._check()
    return dict(source=deepcopy(history._anchor), view=deepcopy(history._ctx.factual['evidence_state']))


def _bundle(history, refs):
    """Original B1 support including relationship/contradiction closure, never aliases."""
    clauses = {c['id']: c for c in history._ctx.factual['clauses']}
    edges = {r['id']: r for r in history._ctx.related['relationships']}
    units = {**clauses, **edges}
    if not set(refs) <= units.keys():
        raise ValueError('FINDINGS_UNKNOWN_ORIGINAL_REFERENCE')
    meter = b1.Meter(b1.Limits(), time.monotonic)
    needed = set(refs) & clauses.keys()
    for ref in refs:
        needed.update(edges.get(ref, {}).get('endpoints', []))
    conflicts = {}
    for edge in edges.values():
        if edge['predicate'] == 'incompatible_recorded_field':
            for cid in edge['endpoints']:
                conflicts.setdefault(cid, []).append(edge)
    # Closure must preserve contrary endpoints even when not explicitly cited.
    pending = list(needed)
    while pending:
        cid = pending.pop()
        for edge in conflicts.get(cid, []):
            for endpoint in edge['endpoints']:
                if endpoint not in needed:
                    needed.add(endpoint)
                    pending.append(endpoint)
    hydrated = {cid: b1._rehydrate(clauses[cid], history._ctx, meter) for cid in sorted(needed)}
    bundles = []
    for ref in refs:
        value = d2._closure(units[ref], clauses, hydrated, conflicts, meter)
        if value is None:
            raise ValueError('FINDINGS_SUPPORT_UNAVAILABLE')
        bundles.append(value)
    return bundles


def _manual(history, kind, statement, supports, contrary, explanation='', limitations=None):
    if kind not in KINDS or kind in ('ai_proposal', 'analyst_reviewed_conclusion'):
        raise ValueError('FINDINGS_CANDIDATE_KIND')
    _text(statement, 2048); _text(explanation, empty=True)
    _refs(supports); _refs(contrary)
    if not supports:
        raise ValueError('FINDINGS_SUPPORT_REQUIRED')
    limitations = [] if limitations is None else limitations
    if type(limitations) is not list or len(limitations) > 32:
        raise ValueError('FINDINGS_LIMITATIONS')
    for line in limitations:
        _text(line, 2048)
    if kind != 'analyst_hypothesis':
        clauses = {c['id']: c for c in history._ctx.factual['clauses']}
        relations = {r['id'] for r in history._ctx.related['relationships']}
        expected = 'observation' if kind == 'original_observation' else 'deterministic_interpretation'
        if not all(ref in relations if kind == 'deterministic_relationship'
                   else clauses.get(ref, {}).get('type') == expected for ref in supports):
            raise ValueError('FINDINGS_CLASSIFICATION_SUPPORT')
    return dict(origin=kind, statement=statement, explanation=explanation,
                supporting_ids=deepcopy(supports), contrary_ids=deepcopy(contrary),
                support=_bundle(history, supports), contrary=_bundle(history, contrary),
                limitations=deepcopy(limitations), recommendations=[],
                assertion_authority='analyst-supplied unverified text; references do not prove entailment',
                ai=None)


def _prepared(history, capsule):
    from . import d2_execution as ex, d2_cross as cross
    _keys(capsule, 'model profile version options question raw request_id packet_digest item')
    _text(capsule['model'], 256); _text(capsule['raw'], 16384)
    if type(capsule['item']) is not int or not 0 <= capsule['item'] < 4:
        raise ValueError('FINDINGS_AI_ITEM')
    h = (cross.History(history, capsule['question'], capsule['model'], capsule['version'])
         if capsule['profile'] == cross.VERSION else history)
    preview = h.preview(**capsule['options'])
    packet = next((p for p in preview['packets'] if p['request_id'] == capsule['request_id']), None)
    if packet is None or packet['packet_digest'] != capsule['packet_digest']:
        raise ValueError('FINDINGS_AI_REQUEST_BINDING')
    return ex.Prepared(h, packet, dict(provider='openai', model=capsule['model']),
                       capsule['options'], profile=capsule['profile'], response_version=capsule['version'])


def _ai(history, capsule):
    from .d2_execution import validate_model_response
    prepared = _prepared(history, capsule)
    validated, _ = validate_model_response(prepared, capsule['raw'])
    if capsule['item'] >= len(validated['proposals']):
        raise ValueError('FINDINGS_AI_ITEM')
    proposal = validated['proposals'][capsule['item']]
    item = proposal['item']
    if item['kind'] != 'hypothesis':
        raise ValueError('FINDINGS_NOT_A_FINDING_PROPOSAL')
    body = prepared.packet['content']
    aliases = {s['alias']: body['clauses'][s['clause_ref']] for s in body['supports']}
    supports = sorted({aliases[a] for a in item['support_refs']})
    contrary = sorted({aliases[a] for a in item['contradictory_refs']})
    supports = sorted(set(supports + proposal['validated_relationship_ids']))
    # The validated proposal retains exact field provenance, interpretation premises,
    # alternatives and qualifications. Alias text is retained as request-local context only.
    return dict(origin='ai_proposal', statement=item['statement'], explanation='',
                supporting_ids=supports, contrary_ids=contrary,
                support=_bundle(history, supports), contrary=_bundle(history, contrary),
                limitations=deepcopy(proposal['mandatory_qualifications']),
                recommendations=[dict(question=body['question'], action=item['next_examination'],
                    discriminating_outcomes=item.get('discriminator', ''), artifact_family='not structurally specified',
                    availability='unknown', execution='unexecuted')]
                    if item.get('next_examination') else [],
                assertion_authority='unverified AI proposal; analyst acceptance is not forensic verification',
                ai=dict(capsule=deepcopy(capsule), validated=deepcopy(proposal)))


def _candidate_shape(value):
    _keys(value, 'origin statement explanation supporting_ids contrary_ids support contrary limitations recommendations assertion_authority ai')
    if value['origin'] not in KINDS[:-1]:
        raise ValueError('FINDINGS_ORIGIN')
    _text(value['statement'], 2048); _text(value['explanation'], empty=True)
    _refs(value['supporting_ids']); _refs(value['contrary_ids'])
    if not value['supporting_ids']:
        raise ValueError('FINDINGS_SUPPORT_REQUIRED')
    for key in ('support', 'contrary', 'limitations', 'recommendations'):
        if type(value[key]) is not list or len(value[key]) > 64:
            raise ValueError('FINDINGS_PAYLOAD')
    if (value['origin'] == 'ai_proposal') != (type(value['ai']) is dict):
        raise ValueError('FINDINGS_AI_BOUNDARY')
    for r in value['recommendations']:
        if r.get('execution') != 'unexecuted' or r.get('availability') != 'unknown':
            raise ValueError('FINDINGS_EXAMINATION_NOT_EXECUTED')


def _validate_candidate(history, value):
    _candidate_shape(value)
    expected = (_ai(history, value['ai']['capsule']) if value['origin'] == 'ai_proposal'
                else _manual(history, value['origin'], value['statement'], value['supporting_ids'],
                             value['contrary_ids'], value['explanation'], value['limitations']))
    if value != expected:
        raise ValueError('FINDINGS_ORIGINAL_SUPPORT_CHANGED')


def _reduce(metadata, events):
    findings, history = {}, []
    previous = digest(metadata)
    total = 0
    for sequence, raw, stored_hash in events:
        total += len(raw.encode('utf-8'))
        if total > MAX_TOTAL or sequence != len(history) + 1 or sequence > MAX_EVENTS or len(raw.encode('utf-8')) > MAX_EVENT:
            raise ValueError('FINDINGS_EVENT_BOUNDS')
        e = loads(raw, max_bytes=MAX_EVENT)
        _keys(e, 'contract workspace_id sequence previous timestamp actor action finding_id payload')
        if (type(e['sequence']) is not int or e['contract'] != CONTRACT or e['workspace_id'] != metadata['id'] or
                e['sequence'] != sequence or e['previous'] != previous or digest(e) != stored_hash):
            raise ValueError('FINDINGS_EVENT_INTEGRITY')
        if datetime.fromisoformat(e['timestamp']).tzinfo is None:
            raise ValueError('FINDINGS_TIMESTAMP')
        _text(e['actor'], 256); _id(e['finding_id'])
        fid, p = e['finding_id'], e['payload']
        if e['action'] in ('propose', 'supersede'):
            expected = 'candidate' if e['action'] == 'propose' else 'candidate replaces rationale previous_state new_state finding_revision'
            _keys(p, expected); _candidate_shape(p['candidate'])
            if fid in findings:
                raise ValueError('FINDINGS_DUPLICATE_ID')
            if e['action'] == 'supersede':
                old = findings.get(p['replaces'])
                _text(p['rationale'])
                if (old is None or old['state'] != 'accepted' or p['previous_state'] != 'accepted'
                        or p['new_state'] != 'superseded' or type(p['finding_revision']) is not int or p['finding_revision'] != old['last_revision']):
                    raise ValueError('FINDINGS_INVALID_SUPERSESSION')
                old.update(state='superseded', superseded_by=fid, last_revision=sequence)
            findings[fid] = dict(contract=FINDING, id=fid, workspace_id=metadata['id'],
                created=e['timestamp'], creation_revision=sequence, last_revision=sequence,
                state='proposed', reviewed_classification=None, replaces=p.get('replaces'),
                superseded_by=None, candidate=deepcopy(p['candidate']))
        elif e['action'] in ('accept', 'reject'):
            _keys(p, 'previous_state new_state finding_revision rationale')
            old = findings.get(fid)
            target = 'accepted' if e['action'] == 'accept' else 'rejected'
            if (old is None or old['state'] != 'proposed' or p['previous_state'] != old['state'] or
                    p['new_state'] != target or type(p['finding_revision']) is not int or p['finding_revision'] != old['last_revision']):
                raise ValueError('FINDINGS_INVALID_REVIEW_TRANSITION')
            _text(p['rationale'], empty=True)
            old.update(state=target, last_revision=sequence,
                       reviewed_classification='analyst_reviewed_conclusion' if target == 'accepted' else None)
        else:
            raise ValueError('FINDINGS_UNKNOWN_EVENT')
        history.append({**e, 'hash': stored_hash, 'actor_authority': 'locally asserted'})
        previous = stored_hash
    return dict(revision=len(history), head=previous, findings=list(findings.values()), history=history)


class Workspace:
    """Reusable service. Retrieval opens SQLite read-only; writes never create files."""
    def __init__(self, directory):
        self.directory = local_path(directory)
        if self.directory.suffix != '.findings':
            raise ValueError('FINDINGS_DIRECTORY_SUFFIX')
        self.path = self.directory / 'findings.sqlite3'

    @contextmanager
    def _connection(self, write=False):
        with DirectoryGuard(self.directory):
            local_path(self.path)
            info = self.path.stat()
            if not self.path.is_file() or info.st_nlink != 1 or info.st_size > MAX_TOTAL * 2:
                raise ValueError('FINDINGS_UNSAFE_FILE')
            for suffix in ('-journal', '-wal', '-shm'):
                side = Path(str(self.path) + suffix)
                local_path(side)
                if side.exists() and side.stat().st_nlink != 1:
                    raise ValueError('FINDINGS_UNSAFE_SIDECAR')
            conn = sqlite3.connect(self.path.as_uri() + ('?mode=rw' if write else '?mode=ro'), uri=True, timeout=2)
            try:
                conn.execute('PRAGMA trusted_schema=OFF')
                if not write:
                    conn.execute('PRAGMA query_only=ON')
                if conn.execute('PRAGMA application_id').fetchone()[0] != APP_ID or conn.execute('PRAGMA user_version').fetchone()[0] != 1:
                    raise ValueError('FINDINGS_SCHEMA_VERSION')
                objects = conn.execute("SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name").fetchall()
                if objects != [('table', 'events'), ('table', 'metadata')]:
                    raise ValueError('FINDINGS_UNEXPECTED_SCHEMA_OBJECT')
                conn.execute('BEGIN IMMEDIATE' if write else 'BEGIN')
                yield conn
                if write:
                    conn.commit()
            except BaseException:
                conn.rollback()
                raise
            finally:
                conn.close()

    def _load(self, conn):
        rows = conn.execute('SELECT value FROM metadata').fetchall()
        if len(rows) != 1 or len(rows[0][0].encode('utf-8')) > 16384:
            raise ValueError('FINDINGS_METADATA')
        metadata = loads(rows[0][0], max_bytes=16384)
        _keys(metadata, 'contract id created actor source_root binding')
        _id(metadata['id']); _text(metadata['actor'], 256)
        if metadata['contract'] != CONTRACT:
            raise ValueError('FINDINGS_SCHEMA_VERSION')
        _text(metadata['source_root'], 4096)
        if datetime.fromisoformat(metadata['created']).tzinfo is None:
            raise ValueError('FINDINGS_TIMESTAMP')
        _keys(metadata['binding'], 'source view')
        _keys(metadata['binding']['source'], 'run_id manifest_sha256 event_head')
        _id(metadata['binding']['source']['run_id'])
        for key in ('manifest_sha256', 'event_head'):
            if not isinstance(metadata['binding']['source'][key], str) or not re.fullmatch('[a-f0-9]{64}', metadata['binding']['source'][key]):
                raise ValueError('FINDINGS_SOURCE_DIGEST')
        from .transcript import validate_evidence_state
        validate_evidence_state(metadata['binding']['view'])
        count, size = conn.execute('SELECT count(*), coalesce(sum(length(CAST(body AS BLOB))),0) FROM events').fetchone()
        if count > MAX_EVENTS or size > MAX_TOTAL:
            raise ValueError('FINDINGS_STORE_BOUNDS')
        events = conn.execute('SELECT sequence, body, hash FROM events ORDER BY sequence').fetchall()
        return metadata, _reduce(metadata, events)

    def _source(self, metadata):
        try:
            h = d2.open_history(metadata['source_root'], metadata['binding']['source']['run_id'])
            if _binding(h) != metadata['binding']:
                return None, 'invalid_source_binding'
            return h, 'valid_recorded_binding'
        except OSError:
            return None, 'unresolved_source_unavailable'
        except (ValueError, KeyError, TypeError):
            return None, 'invalid_source_binding'

    def export(self):
        with self._connection() as conn:
            metadata, state = self._load(conn)
        h, status = self._source(metadata)
        if h is not None:
            for f in state['findings']:
                _validate_candidate(h, f['candidate'])
            h._check()
        return dict(contract=CONTRACT, metadata=metadata, source_binding_status=status,
                    source_validation='verified against recorded history' if h else 'support not revalidated; do not treat as evidence',
                    authority='local analyst decisions, not forensic verification', **state)

    def list(self):
        result = self.export()
        return {k: result[k] for k in ('revision', 'source_binding_status', 'source_validation', 'findings')}

    def get(self, identity):
        result = self.list()
        result['findings'] = [f for f in result['findings'] if f['id'] == identity]
        if not result['findings']:
            raise ValueError('FINDINGS_UNKNOWN_ID')
        return result

    def decisions(self, identity=None):
        result = self.export()
        return dict(revision=result['revision'], source_binding_status=result['source_binding_status'],
            history=[e for e in result['history'] if identity is None or e['finding_id'] == identity or e['payload'].get('replaces') == identity])

    def _write(self, action, actor, expected_revision, build, finding_id=None):
        _text(actor, 256)
        if type(expected_revision) is not int or expected_revision < 0:
            raise ValueError('FINDINGS_EXPECTED_REVISION')
        with self._connection(True) as conn:
            metadata, state = self._load(conn)
            if state['revision'] != expected_revision:
                raise ValueError('FINDINGS_STALE_REVISION')
            h, status = self._source(metadata)
            if h is None:
                raise ValueError('FINDINGS_' + status.upper())
            for f in state['findings']:
                _validate_candidate(h, f['candidate'])
            fid = uuid.uuid4().hex if finding_id is None else _id(finding_id)
            payload = build(h, state)
            e = dict(contract=CONTRACT, workspace_id=metadata['id'], sequence=state['revision'] + 1,
                     previous=state['head'], timestamp=_stamp(), actor=actor, action=action, finding_id=fid, payload=payload)
            raw = encoded(e)
            # Validate transitions before writing, using the same deterministic replay.
            rows = conn.execute('SELECT sequence, body, hash FROM events ORDER BY sequence').fetchall()
            _reduce(metadata, rows + [(e['sequence'], raw, digest(e))])
            h._check()
            conn.execute('INSERT INTO events VALUES (?,?,?)', (e['sequence'], raw, digest(e)))
        return fid

    def register(self, *, actor, expected_revision, kind, statement, supporting_ids, contrary_ids=(), explanation='', limitations=()):
        return self._write('propose', actor, expected_revision,
            lambda h, s: dict(candidate=_manual(h, kind, statement, list(supporting_ids), list(contrary_ids), explanation, list(limitations))))

    def import_d2(self, prepared, response_text, item_index, *, actor, expected_revision):
        """Explicit import of an available response, revalidated without model execution.

        A claimed status=accepted JSON object is not accepted as an input capability.
        This verifies mechanical validity, not that a provider actually authored text.
        """
        from .d2_execution import Prepared
        if type(prepared) is not Prepared:
            raise ValueError('FINDINGS_PREPARED_REQUIRED')
        prepared.check()
        capsule = dict(model=prepared.config['model'], profile=prepared.profile, version=prepared.response_version,
            options=deepcopy(prepared.options), question=prepared.packet['content']['question'], raw=response_text,
            request_id=prepared.packet['request_id'], packet_digest=prepared.packet['packet_digest'], item=item_index)
        def build(h, state):
            if prepared.packet['content']['source'] != h._anchor or prepared.packet['content']['view'] != h._ctx.factual['evidence_state']:
                raise ValueError('FINDINGS_AI_SOURCE_BINDING')
            return dict(candidate=_ai(h, capsule))
        return self._write('propose', actor, expected_revision, build)

    def import_result(self, prepared, validated_result, item_index, *, actor, expected_revision):
        """Import an available D2 quality result, not provider logs or usage metadata.

        Re-encode its lossless structured fields and require exact revalidation of
        the entire result before registering one candidate. No execute() changes.
        """
        from . import d2_execution as ex, d2_quality as quality, d2_wire as wire
        if type(prepared) is not ex.Prepared or type(validated_result) is not dict:
            raise ValueError('FINDINGS_VALIDATED_RESULT_REQUIRED')
        if validated_result.get('contract') != 'd2-quality-validation-v1':
            raise ValueError('FINDINGS_QUALITY_RESULT_REQUIRED')
        prepared.check()
        accounts = []
        try:
            for proposal in validated_result['proposals']:
                item = proposal['item']
                accounts.append(dict(s=item['statement'], e=item['support_refs'], c=item['contradictory_refs'],
                    i=item['interpretation_refs'], a=item['alternatives'][0] if item['alternatives'] else '',
                    u=item['assumptions'][0] if item['assumptions'] else '',
                    d=item['discriminator'], n=item['next_examination']))
            raw = wire.J(dict(v=prepared.response_version, o=validated_result['reasoning_outcome'], a=accounts,
                r=validated_result.get('outcome_rationale', validated_result.get('abstention_reason', ''))))
            checked, _ = ex.validate_model_response(prepared, raw)
        except (KeyError, TypeError, IndexError) as exc:
            raise ValueError('FINDINGS_INVALID_VALIDATED_RESULT') from exc
        if checked != validated_result:
            raise ValueError('FINDINGS_VALIDATED_RESULT_CHANGED')
        return self.import_d2(prepared, raw, item_index, actor=actor, expected_revision=expected_revision)

    def review(self, identity, decision, *, actor, expected_revision, rationale=''):
        if decision not in ('accept', 'reject'):
            raise ValueError('FINDINGS_DECISION')
        def build(h, state):
            f = next((f for f in state['findings'] if f['id'] == identity), None)
            if f is None:
                raise ValueError('FINDINGS_UNKNOWN_ID')
            return dict(previous_state=f['state'], new_state='accepted' if decision == 'accept' else 'rejected',
                        finding_revision=f['last_revision'], rationale=rationale)
        return self._write(decision, actor, expected_revision, build, identity)

    def supersede(self, identity, *, actor, expected_revision, rationale, statement, supporting_ids,
                  contrary_ids=(), explanation='', limitations=()):
        def build(h, state):
            old = next((f for f in state['findings'] if f['id'] == identity), None)
            if old is None:
                raise ValueError('FINDINGS_UNKNOWN_ID')
            return dict(candidate=_manual(h, 'analyst_hypothesis', statement, list(supporting_ids), list(contrary_ids), explanation, list(limitations)),
                        replaces=identity, rationale=rationale, previous_state=old['state'], new_state='superseded', finding_revision=old['last_revision'])
        return self._write('supersede', actor, expected_revision, build)


def create(directory, source_root, run_id, *, actor):
    """Exclusively reserve a new directory; never reuse or overwrite an evidence file."""
    _text(actor, 256)
    h = d2.open_history(source_root, run_id)
    workspace = Workspace(directory)
    source_root = local_path(source_root)
    # Do not write below a transcript root, case workspace, or a recorded case path.
    if workspace.directory.is_relative_to(source_root):
        raise ValueError('FINDINGS_PROTECTED_SOURCE_DESTINATION')
    for parent in (workspace.directory, *workspace.directory.parents):
        if (parent / 'case.db').exists() or (parent / 'manifest.json').exists() or parent.name.endswith('.investigations'):
            raise ValueError('FINDINGS_PROTECTED_CASE_DESTINATION')
    metadata = dict(contract=CONTRACT, id=uuid.uuid4().hex, created=_stamp(), actor=actor,
                    source_root=str(source_root), binding=_binding(h))
    with DirectoryGuard(workspace.directory.parent):
        workspace.directory.mkdir()  # Exclusive; no deletion of caller directories on failure.
        with DirectoryGuard(workspace.directory):
            fd = os.open(workspace.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
            conn = sqlite3.connect(workspace.path.as_uri() + '?mode=rw', uri=True)
            try:
                conn.execute('BEGIN IMMEDIATE')
                conn.execute(f'PRAGMA application_id={APP_ID}')
                conn.execute('PRAGMA user_version=1')
                conn.execute('CREATE TABLE metadata (value TEXT NOT NULL)')
                conn.execute('CREATE TABLE events (sequence INTEGER PRIMARY KEY, body TEXT NOT NULL, hash TEXT NOT NULL)')
                conn.execute('INSERT INTO metadata VALUES (?)', (encoded(metadata),))
                h._check()
                conn.commit()
            except BaseException:
                conn.rollback()
                raise
            finally:
                conn.close()
    return workspace


def main():
    p = argparse.ArgumentParser(description='Local analyst findings; no provider calls or evidence lookups')
    p.add_argument('directory')
    sub = p.add_subparsers(dest='command', required=True)
    c = sub.add_parser('create'); c.add_argument('source_root'); c.add_argument('run_id'); c.add_argument('--actor', required=True)
    sub.add_parser('export')
    for name in ('propose', 'accept', 'reject', 'supersede'):
        q = sub.add_parser(name); q.add_argument('--actor', required=True); q.add_argument('--revision', type=int, required=True)
        if name != 'propose': q.add_argument('finding_id')
        if name in ('propose', 'supersede'):
            q.add_argument('--statement', required=True); q.add_argument('--support', action='append', required=True)
            q.add_argument('--contrary', action='append', default=[])
        if name == 'propose': q.add_argument('--kind', default='analyst_hypothesis', choices=KINDS[:3] + ('analyst_hypothesis',))
        else: q.add_argument('--rationale', default='')
    a = p.parse_args()
    if a.command == 'create': result = create(a.directory, a.source_root, a.run_id, actor=a.actor).export()
    else:
        w = Workspace(a.directory)
        if a.command == 'export': result = w.export()
        elif a.command == 'propose': result = w.register(actor=a.actor, expected_revision=a.revision, kind=a.kind, statement=a.statement, supporting_ids=a.support, contrary_ids=a.contrary)
        elif a.command == 'supersede': result = w.supersede(a.finding_id, actor=a.actor, expected_revision=a.revision, rationale=a.rationale, statement=a.statement, supporting_ids=a.support, contrary_ids=a.contrary)
        else: result = w.review(a.finding_id, a.command, actor=a.actor, expected_revision=a.revision, rationale=a.rationale)
    print(encoded(result))


if __name__ == '__main__':
    main()
