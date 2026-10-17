"""Opt-in synthetic scale comparison; real read-only workers, mocked proposals."""
import argparse
import json
import logging
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forensic_assistant.investigation_ai.controller import run
from forensic_assistant.investigation_ai.runner import ForensicWorker
from forensic_assistant.investigation_ai.state import Budget


class LegacyWorker(ForensicWorker):
    def __init__(self, config):
        super().__init__({k: v for k, v in config.items() if k != '_snapshot_dir'})


class Proposal:
    def complete(self, messages, schema):
        record = json.loads(messages[1]['content'])['UNTRUSTED FORENSIC EVIDENCE']['records'][0]
        return json.dumps(dict(action='tool', tool='show_evidence',
                              arguments=dict(evidence_id=record['id']), reason='Inspect record'))


class Timings(logging.Handler):
    def __init__(self):
        super().__init__()
        self.fingerprints = []
    def emit(self, record):
        if record.msg.startswith('investigate-ai startup stage=%s') and record.args[:2] == ('fingerprint', 'complete'):
            self.fingerprints.append(record.args[2])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', required=True, help='Accessible synthetic scale fixture only')
    parser.add_argument('--transcripts', required=True)
    args = parser.parse_args()
    logger = logging.getLogger('forensic_assistant.investigation_ai')
    logger.setLevel(logging.DEBUG)
    fingerprints = set()
    for dry_run in (True, False):
        for label, factory in (('before', LegacyWorker), ('after', ForensicWorker)):
            timings = Timings()
            logger.addHandler(timings)
            try:
                result = run(dict(case_path=args.case, semantic_enabled=False),
                    'Did coreupdater.exe execute after loot.zip was downloaded?', args.transcripts,
                    client=Proposal(), worker_factory=factory, dry_run=dry_run,
                    approval=lambda *_: True, budget=Budget(steps=1, seconds=300))
            finally:
                logger.removeHandler(timings)
            fingerprints.add(result['evidence_fingerprint'])
            print(json.dumps(dict(mode='dry-run' if dry_run else 'one-tool', variant=label,
                termination=result['termination'], fingerprint=result['evidence_fingerprint'],
                fingerprint_count=len(timings.fingerprints), fingerprint_seconds=sum(timings.fingerprints),
                elapsed_seconds=result['metrics']['elapsed_seconds'],
                accepted_calls=result['state']['accepted_calls'], snapshot=result['metrics'].get('integrity'))), flush=True)
    assert len(fingerprints) == 1 and None not in fingerprints


if __name__ == '__main__':
    main()
