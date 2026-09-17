import ipaddress
from forensic_assistant.detections.models import Rule
from forensic_assistant.correlation.models import select, unique_observations
from forensic_assistant.correlation.temporal import shift


class FailuresThenSuccess(Rule):
    def evaluate(self, db, event, parameters):
        threshold = parameters["failure_threshold"]
        window = parameters["failure_window_seconds"]
        if not all(event.get(key) for key in ("host_key", "timestamp_utc", "target_account", "source_ip_key")):
            return None
        if ipaddress.ip_address(event["source_ip_key"]).is_unspecified:
            return None
        candidates = select(db, "c.kind='failed_logon' AND c.host_key=? AND c.target_account=? AND c.source_ip_key=? AND c.timestamp_utc>=? AND c.timestamp_utc<? AND (c.target_sid IS NULL OR ? IS NULL OR c.target_sid=?)",
            (event["host_key"], event["target_account"], event["source_ip_key"], shift(event["timestamp_utc"], -window), event["timestamp_utc"], event["target_sid"], event["target_sid"]), limit=1000)
        failures = unique_observations(candidates.records)
        if len(failures) < threshold:
            return None
        return self.observation(event,
            f"At least {len(failures)} distinct failed-logon observations precede a successful logon within {window}s for matching host, account, and source IP",
            evidence_ids=[event["id"], *(e["id"] for e in failures)], parameters=parameters,
            limitations=["Retries, password mistakes, and legitimate administration are possible",
                         "Matching source IP does not identify a unique person; no successful session is inferred for failed attempts",
                         "Failure candidates were capped at 1000" if candidates.truncated else "Identical exported observations counted once; evidence records remain distinct"])


RULES = [FailuresThenSuccess("LOCARD-AUTH-001", "Repeated failures followed by success",
    "Review successful authentication preceded by repeated matching failures", "medium", "1", ("logon",))]
