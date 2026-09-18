import importlib
import pkgutil
from forensic_assistant.detections import rules
from forensic_assistant.database.context import host_key
from forensic_assistant.retrieval.queries import required_time, escape_like
from forensic_assistant.correlation.models import select, unique_observations


def available_rules():
    discovered = []
    for module in sorted(pkgutil.iter_modules(rules.__path__), key=lambda module: module.name):
        discovered.extend(importlib.import_module(rules.__name__ + "." + module.name).RULES)
    if len({rule.rule_id for rule in discovered}) != len(discovered):
        raise ValueError("Duplicate detection rule ID")
    return sorted(discovered, key=lambda rule: rule.rule_id)


def detections(db, *, start=None, end=None, username=None, hostname=None, severity=None,
               rule_id=None, limit=100, candidate_limit=1000, failure_threshold=5, failure_window_seconds=300):
    if not 1 <= limit <= 10000 or not 1 <= candidate_limit <= 10000:
        raise ValueError("Detection limits must be 1..10000")
    if not 2 <= failure_threshold <= 1000 or not 1 <= failure_window_seconds <= 86400:
        raise ValueError("Failure threshold must be 2..1000 and window 1..86400 seconds")
    if severity not in (None, "low", "medium", "high"):
        raise ValueError("Severity must be low, medium, or high")
    all_rules = available_rules()
    if rule_id and rule_id not in {r.rule_id for r in all_rules}:
        raise ValueError("Unknown rule ID")
    if start and end and required_time(start) > required_time(end):
        raise ValueError("Start must not follow end")
    results, coverage = [], []
    parameters = {"failure_threshold": failure_threshold, "failure_window_seconds": failure_window_seconds}
    for rule in all_rules:
        if (rule_id and rule.rule_id != rule_id) or (severity and rule.severity != severity):
            continue
        if getattr(rule,'sources',None):
            from forensic_assistant.retrieval.evidence import EvidenceQueries
            candidates=EvidenceQueries(db).search(artifact=rule.sources[0],evidence_kind=rule.kinds[0],start=start,end=end,username=username,hostname=hostname,limit=candidate_limit)
            coverage.append({'rule_id':rule.rule_id,'candidate_count':candidates.total,'evaluated_count':len(candidates.records),'truncated':candidates.truncated})
            for event in candidates.records:
                if event['artifact_type'] not in rule.kinds:continue
                finding=rule.evaluate(db,event,parameters)
                if finding:results.append(finding)
            continue
        where = "c.kind IN (" + ",".join("?" for _ in rule.kinds) + ")"
        params = list(rule.kinds)
        if start:
            where += " AND c.timestamp_utc>=?"; params.append(required_time(start))
        if end:
            where += " AND c.timestamp_utc<=?"; params.append(required_time(end))
        if hostname:
            where += " AND c.host_key=?"; params.append(host_key(hostname))
        if username:
            where += " AND (e.username=? COLLATE NOCASE OR e.username LIKE ? ESCAPE '!' COLLATE NOCASE)"
            params.extend([username, "%\\" + escape_like(username) if "\\" not in username else escape_like(username)])
        candidates = select(db, where, params, limit=candidate_limit)
        coverage.append({"rule_id": rule.rule_id, "candidate_count": candidates.total,
                         "evaluated_count": len(candidates.records), "truncated": candidates.truncated})
        cross_coverage=[]
        evaluation_parameters={**parameters,'_cross_coverage':cross_coverage}
        for event in unique_observations(candidates.records):
            finding = rule.evaluate(db, event, evaluation_parameters)
            if finding:
                results.append(finding)
        if cross_coverage:
            coverage[-1]['cross_artifact_queries']=len(cross_coverage)
            coverage[-1]['cross_artifact_candidates']=sum(c['candidate_count'] for c in cross_coverage)
            coverage[-1]['cross_artifact_truncated']=any(c['truncated'] for c in cross_coverage)
            coverage[-1]['truncated'] |= coverage[-1]['cross_artifact_truncated']
    results.sort(key=lambda d: (d["timestamp"] is None, d["timestamp"] or "", d["rule_id"], d["detection_id"]))
    return {"detections": results[:limit], "total_evaluated_detections": len(results),
            "truncated": len(results) > limit or any(item["truncated"] for item in coverage),
            "rule_coverage": coverage, "parameters": parameters,
            "severity_meaning": "Static rule review priority, not confidence or probability of compromise",
            "caution": "DETECTION != COMPROMISE. Missing matches do not prove absence of activity."}
