"""Bounded deterministic evidence assembly, reusable without a model."""
from forensic_assistant.correlation.models import get_event, order_key, time_ns
from forensic_assistant.correlation.processes import process_tree, resolve_parent
from forensic_assistant.correlation.sessions import related_logon_events
from forensic_assistant.correlation.temporal import events_around, shift
from forensic_assistant.detections.engine import detections, available_rules
from forensic_assistant.retrieval.queries import Queries, required_time


class Assembly:
    def __init__(self, db, max_candidates):
        if not 1 <= max_candidates <= 10000:
            raise ValueError("Candidate limit must be 1..10000")
        self.db = db
        self.max_candidates = max_candidates
        self.records = {}
        self.known_ids = set()
        self.groups = {key: [] for key in ("anchors", "correlated", "detections", "temporal", "other")}
        self.relationships = []
        self.unresolved = []
        self.limits = []
        self.detected = []
        self.source_counts = []

    def add(self, event, group):
        self.known_ids.add(event["id"])
        if event["id"] not in self.records and len(self.records) >= self.max_candidates:
            self.limits.append("Investigation candidate-record limit reached")
            order = list(self.groups)
            def rank(eid):
                return min(order.index(key) for key, ids in self.groups.items() if eid in ids)
            worst = max(self.records, key=lambda eid: (rank(eid), eid))
            if rank(worst) <= order.index(group):
                return
            self.records.pop(worst)
            for ids in self.groups.values():
                if worst in ids:
                    ids.remove(worst)
        self.records[event["id"]] = event
        if event["id"] not in self.groups[group]:
            self.groups[group].append(event["id"])

    def reference(self, evidence_id, group):
        self.known_ids.add(evidence_id)
        if evidence_id not in self.records and len(self.records) >= self.max_candidates:
            order = list(self.groups)
            worst_rank = max(min(order.index(key) for key, ids in self.groups.items() if eid in ids) for eid in self.records)
            if order.index(group) >= worst_rank:
                self.limits.append("Investigation candidate-record limit reached")
                return
        self.add(self.records.get(evidence_id) or get_event(self.db, evidence_id), group)

    def add_relationships(self, relationships):
        for relation in relationships:
            target = self.unresolved if relation["status"] == "UNRESOLVED" else self.relationships
            if relation not in target:
                target.append(relation)
            for eid in relation["evidence_ids"]:
                self.reference(eid, "correlated" if relation["status"] != "UNRESOLVED" else "other")

    def add_sessions(self, anchor):
        related = related_logon_events(self.db, anchor["id"], limit=min(self.max_candidates, 500))
        for message in related["unresolved"]:
            self.unresolved.append({"relationship": "session", "status": "UNRESOLVED", "evidence_ids": [anchor["id"]], "reason": message})
        for result in related["sessions"]:
            if result["status"] == "UNRESOLVED":
                self.unresolved.append({"relationship": "session", "status": "UNRESOLVED", "evidence_ids": [anchor["id"]], "reason": result["reason"]})
            self.add_relationships(result["relationships"])
            if result["truncated"]:
                self.limits.append("Session candidate limit reached")

    def add_detections(self, result):
        self.detected = result["detections"]
        self.source_counts.extend(result["rule_coverage"])
        if result["truncated"]:
            self.limits.append("Detection candidates or output were bounded; not all rules/events were exhaustively evaluated")
        for finding in self.detected:
            for eid in finding["evidence_ids"]:
                self.reference(eid, "detections")

    def output(self, parameters):
        for relation in self.relationships + self.unresolved:
            relation["omitted_evidence_ids"] = [eid for eid in relation["evidence_ids"] if eid not in self.records]
        for finding in self.detected:
            finding["omitted_evidence_ids"] = [eid for eid in finding["evidence_ids"] if eid not in self.records]
        return {"direct_evidence": [self.records[eid] for eid in self.groups["anchors"]],
                "correlated_evidence": self.relationships, "detections": self.detected,
                "unresolved_relationships": self.unresolved,
                "temporal_neighbor_ids": self.groups["temporal"],
                "evidence_records": sorted(self.records.values(), key=order_key),
                "priorities": self.groups,
                "candidate_count": len(self.known_ids), "candidate_count_is_lower_bound": bool(self.limits),
                "retrieved_record_count": len(self.records),
                "source_query_counts": self.source_counts, "limits": sorted(set(self.limits)),
                "coverage": {
                    "events_without_utc": self.db.execute("SELECT count(*) FROM events WHERE timestamp_utc IS NULL").fetchone()[0],
                    "incomplete_ingestion_runs": self.db.execute("SELECT count(*) FROM ingestion_runs WHERE status<>'complete'").fetchone()[0]},
                "parameters": parameters,
                "caution": "CORRELATION != CAUSATION. DETECTION != COMPROMISE. ABSENCE OF EVIDENCE != EVIDENCE OF ABSENCE."}


def investigate(db, evidence_id, *, seconds=120, max_candidates=500):
    if not 0 <= seconds <= 86400:
        raise ValueError("Investigation seconds must be 0..86400")
    anchor = get_event(db, evidence_id)
    assembled = Assembly(db, max_candidates)
    assembled.add(anchor, "anchors")
    if anchor["kind"] == "process":
        tree = process_tree(db, evidence_id, seconds=max(1, seconds), max_nodes=min(100, max_candidates))
        assembled.add_relationships(tree["relationships"])
        assembled.limits.extend(tree["limits"])
    assembled.add_sessions(anchor)
    if anchor["timestamp_utc"] and anchor["host_key"]:
        result = detections(db, start=shift(anchor["timestamp_utc"], -seconds),
                            end=shift(anchor["timestamp_utc"], seconds), hostname=anchor["host_key"],
                            candidate_limit=max_candidates, limit=min(100, max_candidates))
        # Always evaluate the anchor even if chronological query limits exclude it.
        existing = {d["detection_id"] for d in result["detections"]}
        for rule in available_rules():
            if anchor["kind"] in rule.kinds:
                item = rule.evaluate(db, anchor, result["parameters"])
                if item and item["detection_id"] not in existing:
                    result["detections"].append(item)
        assembled.add_detections(result)
        neighbors = events_around(db, evidence_id, seconds, limit=max_candidates, nearest=True)
        # Sort by distance before enforcing the aggregate candidate cap.
        ordered = sorted(neighbors.records, key=lambda e: (distance(e["timestamp_utc"], anchor["timestamp_utc"]), e["timestamp_utc"], e["id"]))
        for event in ordered:
            if event["id"] != evidence_id:
                assembled.add(event, "temporal")
        assembled.source_counts.append({"query": "temporal", "candidate_count": neighbors.total, "truncated": neighbors.truncated})
        if neighbors.truncated:
            assembled.limits.append("Temporal candidate limit reached")
    else:
        assembled.unresolved.append({"relationship": "temporal", "status": "UNRESOLVED", "evidence_ids": [evidence_id], "reason": "Host or UTC timestamp missing; no cross-host or invented time window used"})
    return assembled.output({"seconds": seconds, "max_candidates": max_candidates})


def distance(left, right):
    return abs(time_ns(left) - time_ns(right))


def timeline_context(db, start, end, *, hostname=None, username=None, max_candidates=500):
    start, end = required_time(start), required_time(end)
    if start > end:
        raise ValueError("Start must not follow end")
    assembled = Assembly(db, max_candidates)
    timeline = Queries(db).events_between(start, end, hostname=hostname, username=username, limit=max_candidates)
    assembled.source_counts.append({"query": "timeline", "candidate_count": timeline.total, "truncated": timeline.truncated})
    if timeline.truncated:
        assembled.limits.append("Timeline candidate limit reached")
    if not timeline.records:
        return assembled.output({"start": start, "end": end, "max_candidates": max_candidates})
    anchor = get_event(db, timeline.records[0]["id"])
    assembled.add(anchor, "anchors")
    # Correlate at most 20 seeds; query bounds and all omissions remain explicit.
    seeds = [event for event in timeline.records if event["artifact_type"] in ("process", "logon")]
    if len(seeds) > 20:
        assembled.limits.append("Timeline correlation seed limit (20) reached")
    for raw in seeds[:20]:
        event = get_event(db, raw["id"])
        if event["kind"] == "process":
            assembled.add_relationships([resolve_parent(db, event)])
        assembled.add_sessions(event)
    assembled.add_detections(detections(db, start=start, end=end, username=username, hostname=hostname,
                                       candidate_limit=max_candidates, limit=min(100, max_candidates)))
    for event in timeline.records:
        assembled.add(event, "temporal")
    return assembled.output({"start": start, "end": end, "max_candidates": max_candidates})
