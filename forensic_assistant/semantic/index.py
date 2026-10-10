"""Rebuild-only derived sidecar. No native index deserialization or pickle."""
from collections import OrderedDict
import json
import os
from pathlib import Path
import re
import sqlite3
import time
import uuid
import math
import struct
from .documents import VERSION, chunks, fingerprint, snapshot
from .model import sha

FORMAT = 1
MAX_VECTORS = 1000000


def default_root(db_path):
    return Path(str(db_path) + '.semantic-index')


def _generation(root):
    root = Path(root)
    pointer = root / 'CURRENT'
    if not pointer.exists():
        raise ValueError('Semantic index unavailable; run semantic build')
    if pointer.stat().st_size > 64:
        raise ValueError('Invalid index pointer')
    name = pointer.read_text(encoding='ascii')
    if not re.fullmatch('[a-f0-9]{32}', name):
        raise ValueError('Invalid index generation')
    path = root / name
    if path.is_symlink():
        raise ValueError('Index generation may not be a symlink')
    return path


def _manifest(root, *, compatible=True):
    path = _generation(root)
    if (path / 'manifest.json').stat().st_size > 65536:
        raise ValueError('Oversized index manifest')
    m = json.loads((path / 'manifest.json').read_text(encoding='utf-8'))
    if not isinstance(m, dict):
        raise ValueError('Malformed semantic manifest')
    required = {
        'format',
        'representation_version',
        'vectors',
        'dimension',
        'model',
        'hashes',
        'eligible',
        'database_fingerprint'
    }
    if not required <= m.keys() or not isinstance(m['model'], dict) or not isinstance(m['hashes'], dict):
        raise ValueError('Incomplete semantic manifest')
    if not isinstance(m['model'].get('packages', {}), dict):
        raise ValueError('Malformed semantic model package identity')
    if type(m['eligible']) is not int or not 0 <= m['eligible'] <= MAX_VECTORS:
        raise ValueError('Invalid evidence count')
    if m.get('format') != FORMAT or (compatible and m.get('representation_version') != VERSION):
        raise ValueError('Incompatible semantic index')
    count = m['vectors']
    if type(count) is not int or not 0 <= count <= MAX_VECTORS or m['dimension'] != 384:
        raise ValueError('Invalid vector dimensions/count')
    if (path / 'vectors.f32').stat().st_size != count * 384 * 4:
        raise ValueError('Invalid vector file size')
    for name in ('vectors.f32', 'mapping.sqlite'):
        if sha(path / name) != m['hashes'][name]:
            raise ValueError('Semantic index integrity check failed')
    return path, m


def build(db, root, model, *, rebuild=False, max_vectors=100000, progress=None):
    if not 1 <= max_vectors <= MAX_VECTORS:
        raise ValueError('Vector workload limit must be 1..1000000')
    from forensic_assistant.reporting.transcripts import safe_path
    root = safe_path(root)
    if (root / 'CURRENT').exists() and not rebuild:
        raise ValueError('Index exists; use semantic rebuild')
    root.mkdir(parents=True, exist_ok=True)
    generation = uuid.uuid4().hex
    stage = root / generation
    stage.mkdir()
    started = time.perf_counter()
    count = eligible = indexed = truncated = 0
    encoded = 0
    totals = dict(over_limit_records=0, chunked_records=0, chunks_created=0)
    total = 0
    pointer = root / (generation + '.pending')
    def notify():
        if progress:
            progress(dict(records=indexed, total=total, vectors=count, elapsed=time.perf_counter() - started,
                          model=model.identity.get('model_id'), device='CPU'))
    def cap(required):
        raise ValueError(f'Semantic build safety cap exceeded: requires at least {required} vectors; configured limit {max_vectors}. No index was published. Increase --max-vectors.')
    cache = OrderedDict()
    mapping = None
    try:
        mapping = sqlite3.connect(stage / 'mapping.sqlite')
        mapping.execute('CREATE TABLE vectors (vector_id INTEGER PRIMARY KEY,evidence_id TEXT NOT NULL,source_type TEXT NOT NULL,artifact_type TEXT NOT NULL,chunk_id TEXT NOT NULL,digest TEXT NOT NULL,text TEXT NOT NULL)')
        mapping.execute('CREATE INDEX evidence ON vectors(evidence_id)')
        with snapshot(db), (stage / 'vectors.f32').open('xb') as stream:
            total = db.execute('SELECT count(*) FROM evidence_records').fetchone()[0]
            notify()
            if total > max_vectors:
                cap(total)
            digest = fingerprint(db)
            pending = []
            def flush(documents):
                nonlocal count, encoded
                missing = {d['digest']: d['text'] for d in documents if d['digest'] not in cache}
                values = model.encode(list(missing.values())) if missing else []
                if len(values) != len(missing):
                    raise ValueError('Invalid embedding output')
                for digest, vector in zip(missing, values):
                    vector = [float(v) for v in vector]
                    if len(vector) != 384 or not all(math.isfinite(v) for v in vector):
                        raise ValueError('Invalid embedding output')
                    norm = math.sqrt(sum(v * v for v in vector))
                    if not math.isfinite(norm) or norm < 1e-8:
                        raise ValueError('Invalid embedding vector norm')
                    cache[digest] = struct.pack('<384f', *(v / norm for v in vector))
                    encoded += 1
                for d in documents:
                    stream.write(cache[d['digest']])
                    cache.move_to_end(d['digest'])
                    mapping.execute(
                        'INSERT INTO vectors VALUES (?,?,?,?,?,?,?)',
                        (
                            count,
                            d['evidence_id'],
                            d['source_type'],
                            d['artifact_type'],
                            d['chunk_id'],
                            d['digest'],
                            d['text']
                        )
                    )
                    count += 1
                while len(cache) > 1024:
                    cache.popitem(last=False)
                notify()
            for (eid,) in db.execute('SELECT evidence_id FROM evidence_records ORDER BY evidence_id'):
                eligible += 1
                accounting = {}
                documents, cut = chunks(db, eid, model, accounting=accounting)
                for key in totals:
                    totals[key] += accounting[key]
                truncated += int(cut)
                if count + len(pending) + len(documents) > max_vectors:
                    cap(count + len(pending) + len(documents))
                pending.extend(documents)
                while len(pending) >= 16:
                    flush(pending[:16])
                    del pending[:16]
                indexed += 1
            if pending:
                flush(pending)
            stream.flush()
            os.fsync(stream.fileno())
        mapping.commit()
        mapping.close()
        m = {
            'format': FORMAT,
            'representation_version': VERSION,
            'model': model.identity,
            'dimension': 384,
            'vectors': count,
            'eligible': eligible,
            'indexed': indexed,
            'skipped': 0,
            'truncated_records': truncated,
            **totals,
            'embedding_computations': encoded,
            'embedding_cache_hits': count - encoded,
            'database_fingerprint': digest,
            'built_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'build_seconds': time.perf_counter() - started,
            'indexing_version': 'Locard V3',
            'hashes': {name: sha(stage / name) for name in ('mapping.sqlite', 'vectors.f32')}
        }
        with (stage / 'manifest.json').open('x', encoding='utf-8') as f:
            f.write(json.dumps(m, sort_keys=True, indent=2))
            f.flush()
            os.fsync(f.fileno())
        pointer = root / (generation + '.pending')
        with pointer.open('x', encoding='ascii') as f:
            f.write(generation)
            f.flush()
            os.fsync(f.fileno())
        notify()
        os.replace(pointer, root / 'CURRENT')
        return {
            **m,
            'state': 'built',
            'notice': 'Derived sensitive data; semantic similarity is not forensic evidence.'
        }
    finally:
        if mapping is not None:
            mapping.close()
        # Remove only this invocation's unpublished UUID generation. Check the
        # pointer even if Ctrl+C arrived immediately after atomic publication.
        try:
            published = (root / 'CURRENT').exists() and (root / 'CURRENT').read_text(encoding='ascii') == generation
            if not published:
                import shutil
                safe_stage = safe_path(stage)
                if safe_stage.parent == root and safe_stage.name == generation:
                    shutil.rmtree(safe_stage)
                safe_path(pointer).unlink(missing_ok=True)
        except (OSError, ValueError, UnicodeError):
            # Uncertain/redirection paths are preserved, never recursively removed.
            pass


def status(db, root):
    try:
        _, m = _manifest(root, compatible=False)
        with snapshot(db):
            current_count = db.execute('SELECT count(*) FROM evidence_records').fetchone()[0]
            current = m['representation_version'] == VERSION and current_count == m['eligible'] and fingerprint(db) == m['database_fingerprint']
        return {**m, 'current_evidence_records': current_count, 'state': 'current' if current else 'stale'}
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error) as exc:
        return {'state': 'unavailable', 'reason': str(exc)}


def eligible_ids(db, filters):
    from forensic_assistant.retrieval.evidence import EvidenceQueries
    from forensic_assistant.retrieval.queries import required_time
    filters = dict(filters)
    start = filters.pop('start', None)
    end = filters.pop('end', None)
    start = required_time(start) if start else None
    end = required_time(end) if end else None
    if start and end and start > end:
        raise ValueError('Start must not follow end')
    clauses, params = EvidenceQueries(db)._where(**filters)
    times = []
    values = []
    for value, op in ((start, '>='), (end, '<=')):
        if value:
            times.append('t.timestamp_utc' + op + '?')
            values.append(value)
    if times:
        clauses.append('EXISTS (SELECT 1 FROM evidence_timestamps t WHERE (t.evidence_id=e.evidence_id OR t.evidence_id=(SELECT key_id FROM registry_values WHERE evidence_id=e.evidence_id)) AND ' + ' AND '.join(times) + ')')
        params += values
    sql = 'SELECT e.evidence_id FROM evidence_records e' + (' WHERE ' + ' AND '.join(clauses) if clauses else '')
    return {r[0] for r in db.execute(sql, params)}


def search(db, root, model, question, *, limit=20, **filters):
    import numpy as np
    try:
        import faiss
    except ImportError as exc:
        raise ValueError('Install Locard optional semantic dependencies first') from exc
    if not 1 <= limit <= 100 or not question.strip() or len(question.encode()) > 1000:
        raise ValueError('Invalid semantic search bounds')
    try:
        path, m = _manifest(root)
    except (OSError, KeyError, TypeError) as exc:
        raise ValueError('Semantic index unavailable or malformed') from exc
    if m['model'] != model.identity:
        raise ValueError('Embedding model/index mismatch; rebuild explicitly')
    with snapshot(db):
        if db.execute('SELECT count(*) FROM evidence_records').fetchone()[0] != m['eligible']:
            raise ValueError('Semantic index is stale; rebuild explicitly')
        if fingerprint(db) != m['database_fingerprint']:
            raise ValueError('Semantic index is stale; rebuild explicitly')
        allowed = eligible_ids(db, filters)
        q = np.asarray(model.encode([question], query=True), dtype='float32')
        if q.shape != (1, 384) or not np.isfinite(q).all():
            raise ValueError('Invalid query embedding')
        norm = float(np.linalg.norm(q))
        if not math.isfinite(norm) or norm < 1e-8:
            raise ValueError('Invalid query vector norm')
        q /= norm
        conn = sqlite3.connect((path / 'mapping.sqlite').resolve().as_uri() + '?mode=ro', uri=True)
        candidates = []
        scanned = 0
        try:
            with (path / 'vectors.f32').open('rb') as stream:
                for offset in range(0, m['vectors'], 4096):
                    n = min(4096, m['vectors'] - offset)
                    block = np.frombuffer(stream.read(n * 384 * 4), dtype='<f4').reshape(n, 384)
                    if not np.isfinite(block).all():
                        raise ValueError('Nonfinite index vector')
                    if not np.allclose(np.linalg.norm(block, axis=1), 1, atol=1e-4):
                        raise ValueError('Invalid index vector norm')
                    rows = conn.execute(
                        'SELECT vector_id,evidence_id,source_type,artifact_type,chunk_id,digest,text FROM vectors WHERE vector_id>=? AND vector_id<? ORDER BY vector_id',
                        (offset, offset + n)
                    ).fetchall()
                    if len(rows) != n or any(r[0] != offset + i for i, r in enumerate(rows)):
                        raise ValueError('Vector mapping mismatch')
                    selected = [i for i, r in enumerate(rows) if r[1] in allowed]
                    if not selected:
                        continue
                    index = faiss.IndexFlatIP(384)
                    index.add(np.ascontiguousarray(block[selected]))
                    scores, positions = index.search(q, len(selected))
                    scanned += len(selected)
                    for score, pos in zip(scores[0], positions[0]):
                        row = rows[selected[int(pos)]]
                        candidates.append((float(score), row))
                    # Keep a bounded candidate pool. Explain potential duplicate suppression loss.
                    candidates = sorted(candidates, key=lambda x: (-x[0], x[1][1], x[1][4]))[:2000]
        finally:
            conn.close()
        results = []
        seen = set()
        signatures = set()
        suppressed = []
        for score, row in candidates:
            if row[1] in seen:
                continue
            # Normalize whitespace only: no removal of host, path, time, or IDs.
            signature = ' '.join(row[6].split())
            if signature in signatures:
                suppressed.append(row[1])
                continue
            seen.add(row[1])
            signatures.add(signature)
            results.append({
                'evidence_id': row[1],
                'source_type': row[2],
                'artifact_type': row[3],
                'chunk_id': row[4],
                'semantic_similarity': score,
                'retrieval_label': 'SEMANTICALLY RETRIEVED',
                'selection_reasons': ['semantic_similarity'],
                'excerpt': row[6][:1000]
            })
            if len(results) >= limit:
                break
        return {
            'results': results,
            'candidate_vectors': scanned,
            'candidate_pool_truncated': scanned > 2000,
            'suppressed_duplicate_ids': suppressed,
            'model': m['model'],
            'representation_version': VERSION,
            'notice': 'SEMANTIC SIMILARITY != FORENSIC EVIDENCE. RAG locates evidence; it does not create evidence.'
        }
