"""Narrow recorded-history facade. No provider, case opener or source writer.

Recorded reconstruction belongs to the neutral investigation service. A
serialized projection never replaces this source/workspace boundary.
"""
from forensic_assistant.investigation_ai import recorded, findings
from forensic_assistant.investigation_ai.storage import local_path
from forensic_assistant.investigation_ai.transcript import digest


class Source:
    def __init__(self, root, run_id, workspace=None):
        self.root = local_path(root)
        self.history = recorded.open_history(self.root, run_id)
        self.binding = self.history.binding()
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
        self.history.verify()
        if self._snapshot() != self.snapshot:
            raise ValueError('RECORDED_REPORT_WORKSPACE_CHANGED')

    def restore(self):
        return self.history.restore_all_support()

    def state(self):
        return self.history.report_state()

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
        visit(self.history.recorded_inputs())
        return paths
