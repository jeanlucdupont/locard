"""Generate fingerprint-backed v4-1 fixtures using real legacy worker verification.

Current investigations deliberately emit a different evidence-state contract.
These fixtures keep historical report/replay security coverage meaningful.
"""
from forensic_assistant.investigation_ai.controller import run as current_run
from forensic_assistant.investigation_ai.runner import ForensicWorker

class LegacyWorker:
    def __init__(self, config, factory=ForensicWorker):
        self.worker = factory({k:v for k,v in config.items() if k != '_transaction_view'})
    def call(self, *args, **kwargs):
        return self.worker.call(*args, **kwargs)
    def close(self):
        self.worker.close()

def run(*args, **kwargs):
    factory = kwargs.pop('worker_factory', ForensicWorker)
    return current_run(*args, worker_factory=lambda cfg: LegacyWorker(cfg, factory), **kwargs)
