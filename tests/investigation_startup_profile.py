"""Opt-in scale diagnostic, not collected by pytest and not a public command.

Use --case for an accessible synthetic case and --transcripts for derived output.
Runs the real worker/read-only/fingerprint/retrieval path with a mocked model;
never depends on inference and never executes a model-proposed tool.
"""
import argparse
import json
import logging
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forensic_assistant import activity
from forensic_assistant.investigation_ai.controller import run
from forensic_assistant.investigation_ai.state import Budget


class Proposal:
    calls = 0
    def complete(self, messages, schema):
        self.calls += 1
        record = json.loads(messages[1]['content'])['UNTRUSTED FORENSIC EVIDENCE']['records'][0]
        return json.dumps({'action': 'tool', 'tool': 'show_evidence',
                           'arguments': {'evidence_id': record['id']}, 'reason': 'Inspect record'})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', required=True)
    parser.add_argument('--transcripts', required=True)
    parser.add_argument('--semantic', action='store_true')
    parser.add_argument('--seconds', type=int, default=300)
    args = parser.parse_args()
    logging.basicConfig(level=logging.WARNING, format='%(message)s')
    logging.getLogger('forensic_assistant.investigation_ai').setLevel(logging.DEBUG)
    client = Proposal()
    with activity.bind(activity.Session(args.case)):
        result = run(dict(case_path=args.case, semantic_enabled=args.semantic,
                          index_root=args.case+'.semantic', model_path=str(Path(args.case).parent/'semantic-models'/'bge')),
                     'Did coreupdater.exe execute after loot.zip was downloaded?', args.transcripts,
                     client=client, dry_run=True, budget=Budget(seconds=args.seconds))
    print(json.dumps({k: result[k] for k in ('termination','evidence_fingerprint','metrics')} |
                     {'mocked_model_calls': client.calls,
                      'accepted_calls': result['state']['accepted_calls'],
                      'requested_calls': result['state']['requested_calls']}))


if __name__ == '__main__':
    main()
