from dataclasses import dataclass, asdict
import hashlib
import json


@dataclass(frozen=True)
class Rule:
    rule_id: str
    name: str
    description: str
    severity: str
    version: str
    kinds: tuple[str, ...]

    def observation(self, event, reason, *, evidence_ids=None, limitations=None, parameters=None):
        ids = sorted(set(evidence_ids or [event["id"]]))
        params = parameters or {}
        key = json.dumps([self.rule_id, self.version, ids, params], sort_keys=True)
        return {"detection_id": "DETECTION:" + hashlib.sha256(key.encode()).hexdigest(),
                "rule_id": self.rule_id, "rule_name": self.name, "rule_version": self.version,
                "timestamp": event["timestamp_utc"], "severity": self.severity,
                "description": self.description, "evidence_ids": ids, "reason": reason,
                "limitations": limitations or ["This observation alone does not establish malicious activity"],
                "parameters": params}

    def evaluate(self, db, event, parameters):
        raise NotImplementedError
