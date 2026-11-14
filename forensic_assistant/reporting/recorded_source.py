"""Narrow recorded-history facade. No provider, case opener or source writer.

Private reconstruction/restoration contracts are confined here. A serialized
projection is never accepted as a replacement for this source boundary.
"""
from copy import deepcopy
import time

from forensic_assistant.investigation_ai import d2, findings, packets, organization, explanation
from forensic_assistant.investigation_ai.storage import local_path
from forensic_assistant.investigation_ai.transcript import digest


class Source:
    def __init__(self, root, run_id, workspace=None):
        self.root = local_path(root)
        self.history = d2.open_history(self.root, run_id)
        self.binding = findings._binding(self.history)
        self.workspace = findings.Workspace(workspace) if workspace is not None else None
        self.snapshot = self._snapshot()
        if self.snapshot is not None:
            if self.snapshot['metadata']['binding'] != self.binding:
                raise ValueError('RECORDED_REPORT_WORKSPACE_BINDING')
            validated = set()
            for finding in self.snapshot['findings']:
                identity = digest(finding['candidate'])
                if identity not in validated:
                    findings._validate_candidate(self.history, finding['candidate'])
                    validated.add(identity)
        self.check()

    def _snapshot(self):
        if self.workspace is None:
            return None
        with self.workspace._connection() as conn:
            metadata, state = self.workspace._load(conn)
        return dict(metadata=metadata, **state)

    def check(self):
        self.history._check()
        if self._snapshot() != self.snapshot:
            raise ValueError('RECORDED_REPORT_WORKSPACE_CHANGED')

    def restore(self):
        """Restore all accepted clauses, without B1 packet-selection omissions."""
        ctx = self.history._ctx
        packets._validate_context(ctx)
        meter = packets.Meter(packets.Limits(), time.monotonic)
        restored = {}
        for clause in ctx.factual['clauses']:
            bundle = packets._rehydrate(clause, ctx, meter)
            if bundle is None:
                raise ValueError('RECORDED_REPORT_SUPPORT_UNAVAILABLE')
            restored[clause['id']] = bundle
        # Every registered relationship must have its original endpoints restored.
        for relation in ctx.related['relationships']:
            if not set(relation['endpoints']) <= restored.keys():
                raise ValueError('RECORDED_REPORT_INCOMPLETE_DEPENDENCY')
        return deepcopy(restored)

    def state(self):
        ctx = self.history._ctx
        manifest = ctx.manifest
        org = None
        pages = []
        # Organization is a B2 contract. Earlier Stage A histories retain their
        # validated S1/S2/S3 state without inventing a C1 checkpoint.
        if manifest['engine'] == 'incremental-s4-b2-v1' and manifest.get('organization_profile') is not None:
            org = organization.reconstruct(self.root, self.binding['source']['run_id'])
            session = explanation._Session(explanation._TOKEN, manifest, ctx.factual, org)
            cursor = None
            while True:
                page = explanation.page(session, cursor)
                pages.append(page)
                if len(pages) > explanation.MAX_STATEMENTS + 1:
                    raise ValueError('RECORDED_REPORT_PAGE_LIMIT')
                cursor = page['next_cursor']
                if cursor is None:
                    break
        self.check()
        _, events = d2._read(self.root, self.binding['source']['run_id'])
        terminal = next((e['data'] for e in reversed(events) if e['kind'] == 'terminal'), {})
        execution = dict(manifest_status=manifest['status'], terminal_present=bool(terminal),
                         recorded={k: deepcopy(terminal[k]) for k in ('termination', 'primary_termination',
                             'analysis_coverage', 'controller_diagnostic', 'limitations', 'cleanup') if k in terminal})
        self.check()
        return dict(factual=deepcopy(ctx.factual), related=deepcopy(ctx.related),
                    original_assessment=deepcopy(self.history._original),
                    question=manifest['question'], engine=manifest['engine'],
                    frontiers=dict(manifest_chain=deepcopy(manifest['chain']),
                                   accepted=sorted([list(v) for v in ctx.accepted])),
                    organization=org, explanation_pages=pages, execution=execution,
                    historical_proposals=deepcopy((terminal.get('synthesis') or {}).get('accepted', [])))

    def protected_paths(self):
        """Known input containers only; never query a live case for locations."""
        paths = [self.root]
        if self.workspace is not None:
            paths.append(self.workspace.directory)
            paths.append(local_path(self.snapshot['metadata']['source_root']))
        # Physical case/source paths recorded in the manifest, when present,
        # remain protected. They are not opened and are not renderer inputs.
        def visit(value):
            if isinstance(value, dict):
                for key, child in value.items():
                    if key in ('case', 'case_path', 'db_path', 'source_path', 'source_file', 'source_root', 'evidence_root') and isinstance(child, str):
                        from pathlib import Path
                        if Path(child).is_absolute():
                            paths.append(Path(child) if key.endswith('root') else Path(child).parent)
                    else:
                        visit(child)
            elif isinstance(value, list):
                for child in value:
                    visit(child)
        visit(self.history._ctx.manifest)
        visit(list(self.history._ctx.state.records.values()))
        return paths
