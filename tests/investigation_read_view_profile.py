"""Opt-in synthetic phase measurement; never opens an existing case."""
import json
from pathlib import Path
import sys
import time

from forensic_assistant.database.db import connect
from forensic_assistant.investigation_ai import controller, runner
from test_v4_worker import make_case, config
from test_v4_controller import tool
from v1_fixtures import process


def main(root, records=128):
    root = Path(root)
    root.mkdir(exist_ok=False)
    path = root / 'synthetic.db'
    event = make_case(path)
    db = connect(path)
    for i in range(2, records + 1):
        process(db, i, str(i))
    with db:
        db.execute('UPDATE events SET raw_xml=?', ('<synthetic>' + 'x' * 131072 + '</synthetic>',))
    db.close()
    values = {}
    operation = None
    original_record = runner.record
    def record(item):
        original_record(item)
        if item['event'] == 'complete':
            key = str(operation) + '.' + item['stage']
            values[key] = values.get(key, 0) + item['seconds']
    runner.record = record
    class Worker(runner.ForensicWorker):
        def __init__(self, cfg):
            began = time.perf_counter()
            super().__init__(cfg)
            values['worker_start'] = time.perf_counter() - began
        def call(self, name, *args, **kwargs):
            nonlocal operation
            operation = name
            return super().call(name, *args, **kwargs)
        def close(self):
            began = time.perf_counter()
            try:
                super().close()
            finally:
                values['cleanup'] = time.perf_counter() - began
    class Model:
        def complete(self, *args):
            values['until_first_model'] = time.perf_counter() - began
            return json.dumps(tool('show_evidence', {'evidence_id': event['id']}))
    began = time.perf_counter()
    try:
        result = controller.run(config(path), 'PowerShell', root/'runs',
                                client=Model(), worker_factory=Worker, dry_run=True)
    finally:
        runner.record = original_record
    values['initialization'] = result['metrics']['phase_seconds']['initial_operation']
    phases = result['metrics']['phase_seconds']
    values['final_verification'] = phases.get('view_validation', phases.get('final_fingerprint', 0))
    print(json.dumps({'synthetic_records':records, 'database_bytes':path.stat().st_size,
        'seconds':values, 'integrity':result['metrics']['integrity'],
        'termination':result['termination']}, indent=2))

if __name__ == '__main__':
    main(sys.argv[1], int(sys.argv[2]) if len(sys.argv)>2 else 128)
