"""Conservative process graph reconstruction; matching PIDs alone is insufficient."""
from collections import deque
import ntpath
from forensic_assistant.correlation.models import Relationship, get_event, select, unique_observations, order_key
from forensic_assistant.correlation.temporal import shift


def image_matches(left, right):
    if not left or not right:
        return False
    left, right = left.casefold(), right.casefold()
    if ntpath.dirname(left) and ntpath.dirname(right):
        return ntpath.normpath(left) == ntpath.normpath(right)
    return ntpath.basename(left) == ntpath.basename(right)


def unresolved(child, reason, ids=None):
    return Relationship("parent_process", "UNRESOLVED", ids or [child["id"]], reason,
                        ["No parent creation record is invented; reported parent fields remain in the child evidence"],
                        target_id=child["id"]).as_dict()


def resolve_parent(db, child, lookback_seconds=300, candidate_limit=100):
    if not 1 <= lookback_seconds <= 86400:
        raise ValueError("PID fallback lookback must be 1..86400 seconds")
    if child["kind"] != "process":
        return unresolved(child, "Anchor is not a process creation event")
    if not child["host_key"] or not child["timestamp_utc"]:
        return unresolved(child, "Host or unambiguous timestamp is missing")
    params = [child["host_key"], child["timestamp_utc"], child["id"]]
    where = "c.kind='process' AND c.host_key=? AND c.timestamp_utc<=? AND e.id<>?"
    exact = bool(child["parent_process_guid"])
    if exact and child["parent_process_guid"] == child["process_guid"]:
        return unresolved(child, "Process and parent GUID are identical")
    if exact:
        where += " AND c.process_guid=?"
        params.append(child["parent_process_guid"])
    elif child["ppid"] is not None:
        where += " AND c.pid=? AND c.timestamp_utc>=?"
        params.extend([child["ppid"], shift(child["timestamp_utc"], -lookback_seconds)])
    else:
        return unresolved(child, "No parent GUID or PID")
    result = select(db, where, params, limit=candidate_limit)
    parents = unique_observations(result.records)
    if result.truncated:
        return unresolved(child, "Parent candidate limit reached; completeness cannot be established")
    if len(parents) != 1:
        return unresolved(child, f"Expected one parent candidate, found {len(parents)}")
    parent = parents[0]
    ids = [parent["id"], child["id"]]
    if child["ppid"] is not None and parent["pid"] is not None and child["ppid"] != parent["pid"]:
        return unresolved(child, "Parent GUID and PID disagree", ids)
    if child["parent_process_name"] and parent["process_name"] and not image_matches(child["parent_process_name"], parent["process_name"]):
        return unresolved(child, "Reported parent image conflicts with candidate", ids)
    if not exact:
        if parent["timestamp_utc"] >= child["timestamp_utc"]:
            return unresolved(child, "PID candidate does not unambiguously precede the child", ids)
        if not image_matches(child["parent_process_name"], parent["process_name"]):
            return unresolved(child, "PID candidate lacks corroborating parent image", ids)
        parent_session = parent["process_logon_key"]
        creator_session = child["subject_logon_key"] or child["process_logon_key"]
        if parent_session and creator_session and parent_session != creator_session:
            return unresolved(child, "PID candidate has conflicting session identifiers", ids)
        if parent["username"] and child["username"] and parent["username"].casefold() != child["username"].casefold():
            return unresolved(child, "PID fallback has conflicting account fields", ids)
    # Check the parent's full evidenced lifetime, not just the displayed tree window.
    blockers = select(db, "c.host_key=? AND c.timestamp_utc>? AND c.timestamp_utc<=? AND (c.kind='boot' OR (c.kind='process_end' AND (c.pid=? OR c.process_guid=?)) OR (c.kind='process' AND c.pid=? AND e.id<>?))",
                      (child["host_key"], parent["timestamp_utc"], child["timestamp_utc"], parent["pid"], parent["process_guid"], parent["pid"], child["id"]), limit=1)
    if blockers.total:
        return unresolved(child, "Observed restart, termination, or PID reuse intervenes", ids + [blockers.records[0]["id"]])
    return Relationship("parent_process", "CONFIRMED" if exact else "LIKELY", ids,
                        "Explicit same-host parent/process GUID match" if exact else
                        f"Unique same-host preceding PID candidate within {lookback_seconds}s, matching parent image and no observed contradictions",
                        ["Confirmed means supported by the supplied records, not proof of authenticity"] if exact else
                        ["Incomplete process/termination auditing can hide PID reuse; this is not a confirmed identity"],
                        parent["id"], child["id"]).as_dict()


def process_tree(db, evidence_id, *, lookback_seconds=300, seconds=300, max_nodes=100, max_depth=8):
    if not 1 <= max_nodes <= 500 or not 0 <= max_depth <= 20 or not 1 <= seconds <= 86400:
        raise ValueError("Invalid process-tree bounds")
    anchor = get_event(db, evidence_id)
    if anchor["kind"] != "process":
        raise ValueError("Process tree requires a process creation evidence ID")
    nodes = {anchor["id"]: anchor}
    relationships, seen_edges, visited = [], set(), set()
    queue = deque([(anchor, 0)])
    limits = []
    while queue:
        current, depth = queue.popleft()
        if current["id"] in visited:
            continue
        visited.add(current["id"])
        if depth >= max_depth:
            limits.append("Maximum graph depth reached")
            continue
        parent_edge = resolve_parent(db, current, lookback_seconds)
        edge_key = (parent_edge["source_id"], parent_edge["target_id"], parent_edge["status"])
        if edge_key not in seen_edges:
            seen_edges.add(edge_key); relationships.append(parent_edge)
        if parent_edge["status"] != "UNRESOLVED":
            parent = get_event(db, parent_edge["source_id"])
            if parent["id"] not in nodes:
                if len(nodes) < max_nodes:
                    nodes[parent["id"]] = parent
                    queue.append((parent, depth + 1))
                else:
                    limits.append("Maximum graph nodes reached")
        if not current["timestamp_utc"] or not current["host_key"]:
            continue
        query = select(db, "c.kind='process' AND c.host_key=? AND c.timestamp_utc>=? AND c.timestamp_utc<=? AND e.id<>? AND (c.parent_process_guid=? OR c.ppid=?)",
                       (current["host_key"], current["timestamp_utc"], shift(current["timestamp_utc"], seconds),
                        current["id"], current["process_guid"], current["pid"]), limit=max_nodes)
        if query.truncated:
            limits.append("Child candidate limit reached")
        for child in unique_observations(query.records):
            edge = resolve_parent(db, child, lookback_seconds)
            if edge["status"] != "UNRESOLVED" and edge["source_id"] != current["id"]:
                continue
            key = (edge["source_id"], edge["target_id"], edge["status"])
            if key not in seen_edges:
                seen_edges.add(key); relationships.append(edge)
            if child["id"] not in nodes:
                if len(nodes) >= max_nodes:
                    limits.append("Maximum graph nodes reached")
                    continue
                nodes[child["id"]] = child
                if edge["status"] != "UNRESOLVED":
                    queue.append((child, depth + 1))
    included = set(nodes)
    adjacency = {}
    for edge in relationships:
        if edge["status"] != "UNRESOLVED":
            adjacency.setdefault(edge["source_id"], set()).add(edge["target_id"])
    for edge in relationships:
        pending, reached = [edge["target_id"]], set()
        while pending:
            node = pending.pop()
            if node in reached:
                continue
            reached.add(node)
            pending.extend(adjacency.get(node, ()))
        if edge["source_id"] in reached:
            edge["status"] = "UNRESOLVED"
            edge["reason"] = "Contradictory parent records form a cycle"
    # Edges may reference boundary/blocker evidence outside the displayed nodes; say so.
    for edge in relationships:
        missing = [eid for eid in edge["evidence_ids"] if eid not in included]
        if missing:
            edge["omitted_evidence_ids"] = missing
    return {"anchor_id": evidence_id, "nodes": sorted(nodes.values(), key=order_key),
            "relationships": relationships, "limits": sorted(set(limits)),
            "parameters": {"pid_lookback_seconds": lookback_seconds, "child_window_seconds": seconds,
                           "max_nodes": max_nodes, "max_depth": max_depth},
            "caution": "Reported relationships are not proof of maliciousness; absent process records remain unresolved"}


def related_process_events(db, evidence_id, **kwargs):
    return process_tree(db, evidence_id, **kwargs)
