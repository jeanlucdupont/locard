"""Prioritized bounded bundles; relationships travel with all supporting records."""
import hashlib
import json
from forensic_assistant.llm.prompts import SYSTEM_PROMPT, PROMPT_BYTES, FIELDS


def compact_record(event):
    fields = FIELDS + ("process_guid", "parent_process_guid", "subject_logon_key", "target_logon_key", "process_logon_key")
    result, truncated = {}, []
    for name in fields:
        value = event.get(name)
        if value is None or value in ("", "[]"):
            continue
        # Known mapped events use explicit fields; avoid duplicating whole script payloads.
        if name == "event_data_json" and event.get("artifact_type"):
            continue
        if isinstance(value, str) and name != "id":
            shortened = value[:300]
            while len(json.dumps(shortened, ensure_ascii=True)) > 602:
                shortened = shortened[:-1]
            if shortened != value:
                truncated.append(name)
            value = shortened
        result[name] = value
    if truncated:
        result["truncated_fields"] = truncated
    return result


def context_bundle(context, question, budget=PROMPT_BYTES):
    records = {e["id"]: e for e in context["evidence_records"]}
    metadata = {"candidate_records": context["candidate_count"],
                "candidate_count_is_lower_bound": context["candidate_count_is_lower_bound"],
                "sent_records": 0, "omitted_records": context["candidate_count"],
                "fields_truncated": False, "omitted_relationships": 0, "omitted_detections": 0,
                "omitted_unresolved": 0,
                "retrieval_limits": context["limits"],
                "coverage": context.get("coverage", {}),
                "field_selection": "Normalized fields; full payload/XML available through show --raw",
                "limitations": "Auditing may be incomplete. Correlation is not causation; detections are not compromise."}
    bundle = {"metadata": metadata, "EVIDENCE": [], "DIRECT_EVIDENCE": [],
              "CORRELATED_EVIDENCE": [], "DETECTIONS": [], "UNRESOLVED_RELATIONSHIPS": [], "QUESTION": question}
    sent = set()

    def update():
        metadata["sent_records"] = len(sent)
        metadata["omitted_records"] = context["candidate_count"] - len(sent)
        metadata["fields_truncated"] = any(e.get("truncated_fields") for e in bundle["EVIDENCE"])

    def fits():
        return len(SYSTEM_PROMPT.encode()) + len(json.dumps(bundle, ensure_ascii=True).encode()) <= budget

    def package(ids, section=None, item=None):
        if not set(ids) <= records.keys():
            return False
        new = [eid for eid in dict.fromkeys(ids) if eid not in sent]
        old_length = len(bundle["EVIDENCE"])
        bundle["EVIDENCE"].extend(compact_record(records[eid]) for eid in new)
        sent.update(new)
        if section:
            bundle[section].append(item)
        update()
        # Reserve a few bytes for final omission-counter digit growth.
        if not fits() or len(SYSTEM_PROMPT.encode()) + len(json.dumps(bundle).encode()) > budget - 32:
            del bundle["EVIDENCE"][old_length:]
            sent.difference_update(new)
            if section:
                bundle[section].pop()
            update()
            return False
        return True

    if not fits():
        raise ValueError("Question/context metadata exceeds the local prompt budget")
    for eid in context["priorities"]["anchors"]:
        package([eid], "DIRECT_EVIDENCE", eid)
    if context["priorities"]["anchors"] and not bundle["DIRECT_EVIDENCE"]:
        raise ValueError("Anchor evidence cannot fit the prompt budget; narrow the question or inspect with show")
    for relation in context["correlated_evidence"]:
        slim = {key: relation[key] for key in ("relationship", "status", "evidence_ids", "reason", "limitations")}
        slim["relationship_id"] = "REL:" + hashlib.sha256(json.dumps(slim, sort_keys=True).encode()).hexdigest()[:16]
        if not package(slim["evidence_ids"], "CORRELATED_EVIDENCE", slim):
            metadata["omitted_relationships"] += 1
    for detection in context["detections"]:
        slim = {key: detection[key] for key in ("rule_id", "rule_name", "rule_version", "severity", "evidence_ids", "reason", "limitations")}
        if not package(slim["evidence_ids"], "DETECTIONS", slim):
            metadata["omitted_detections"] += 1
    for group in ("correlated", "detections", "temporal", "other"):
        for eid in context["priorities"][group]:
            package([eid])
    for relation in context["unresolved_relationships"]:
        slim = {key: relation[key] for key in ("relationship", "status", "evidence_ids", "reason")}
        if not package(slim["evidence_ids"], "UNRESOLVED_RELATIONSHIPS", slim):
            metadata["omitted_unresolved"] += 1
    update()
    if records and not bundle["EVIDENCE"]:
        raise ValueError("Anchor evidence cannot fit the prompt budget; narrow the question or inspect with show")
    if not fits():
        raise ValueError("Final evidence metadata exceeds the prompt budget")
    return bundle


def annotate_relationship_support(claim, bundle, text_field="statement"):
    """Carry deterministic uncertainty into displayed analysis, independent of prose."""
    refs = set(claim["evidence_ids"])
    supporting = [r for r in bundle["CORRELATED_EVIDENCE"] if set(r["evidence_ids"]) <= refs]
    if supporting:
        claim["supporting_relationships"] = [{"relationship_id": r["relationship_id"], "status": r["status"]} for r in supporting]
        claim["correlation_status"] = "LIKELY" if any(r["status"] == "LIKELY" for r in supporting) else "CONFIRMED"
        if claim.get("classification") == "CORRELATED" and claim["correlation_status"] == "LIKELY":
            claim[text_field] = "LIKELY relationship (deterministic assessment): " + claim[text_field]
    return claim
