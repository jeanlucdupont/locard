"""Explicit V1 patterns layered over the existing V0 planner."""
import re
from forensic_assistant.correlation.investigation import Assembly, investigate, timeline_context
from forensic_assistant.correlation.models import get_event, select
from forensic_assistant.correlation.sessions import session, logons
from forensic_assistant.detections.engine import detections
from forensic_assistant.retrieval.planner import plan_question
from forensic_assistant.retrieval.queries import Queries

STAMP = r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?(?:Z|[+-]\d\d:\d\d)"


def enrich_result(db, result, max_candidates=500):
    assembled = Assembly(db, max_candidates)
    if not result.records:
        return assembled.output({"retrieval_total": result.total})
    # The first matching record anchors expansion; other matches remain candidates.
    context = investigate(db, result.records[0]["id"], max_candidates=max_candidates)
    for event in context["direct_evidence"]:
        assembled.add(event, "anchors")
    assembled.add_relationships(context["correlated_evidence"])
    assembled.unresolved.extend(context["unresolved_relationships"])
    assembled.add_detections({"detections": context["detections"], "rule_coverage": [], "truncated": False})
    for event in result.records:
        assembled.add(event, "anchors" if event["id"] == result.records[0]["id"] else "other")
    context_records = {event["id"]: event for event in context["evidence_records"]}
    for group, ids in context["priorities"].items():
        for eid in ids:
            if eid in context_records:
                assembled.add(context_records[eid], group)
    assembled.limits.extend(context["limits"])
    assembled.source_counts.extend(context["source_query_counts"])
    assembled.source_counts.append({"query": "question", "candidate_count": result.total, "truncated": result.truncated})
    if result.truncated:
        assembled.limits.append("Question retrieval result limit reached")
    return assembled.output({"retrieval_total": result.total, "correlation_anchor": result.records[0]["id"]})


def retrieve_question(queries, question, date_hint=None, limit=30):
    if not question.strip() or len(question.encode()) > 1000:
        raise ValueError("Question must contain 1..1000 UTF-8 bytes")
    db, lower = queries.db, question.lower()
    evidence = re.search(r"(?:EVTX|MFT):[a-f0-9]{64}:Offset:\d+|PREFETCH:[a-f0-9]{64}:File|REGISTRY:[a-f0-9]{64}:(?:KeyOffset|ValueOffset):\d+", question)
    if evidence:
        return {"operation": "investigate", "evidence_id": evidence.group()}, investigate(db, evidence.group())
    stamps = re.findall(STAMP, question)
    if len(stamps) == 2:
        return {"operation": "timeline", "start": stamps[0], "end": stamps[1]}, timeline_context(db, *stamps)
    artifact=re.search(r'\b(mft|prefetch|registry)\b',lower)
    path=re.search(r'\bpath\s+[\"\']([^\"\']+)[\"\']|\bpath\s+(\S+)',question,re.I)
    if artifact or path:
        from forensic_assistant.retrieval.evidence import EvidenceQueries
        filters={}
        if artifact:filters['artifact']=artifact.group(1)
        if path:filters['path']=path.group(1) or path.group(2)
        process=re.search(r'\b([\w.-]+\.exe)\b',question,re.I)
        if process and not path:filters['process']=process.group(1)
        result=EvidenceQueries(db).timeline_around(stamps[0],limit=limit,**filters) if stamps else EvidenceQueries(db).search(limit=limit,**filters)
        return {'operation':'artifact_search','filters':filters,'notes':['Explicit artifact/path pattern; no semantic search']},enrich_result(db,result)
    logon = re.search(r"\b(?:logon[- ]?id|session)\s*[:=]?\s*(0x[0-9a-f]+|\d+)\b", question, re.I)
    if logon:
        host = re.search(r"\bhost(?:name)?\s+([\w.-]+)", question, re.I)
        result = session(db, logon.group(1), hostname=host.group(1) if host else None, around=stamps[0] if stamps else None)
        assembled = Assembly(db, 500)
        if result.get("anchor_id"):
            assembled.add(get_event(db, result["anchor_id"]), "anchors")
        assembled.add_relationships(result["relationships"])
        if result["status"] == "UNRESOLVED":
            raise ValueError(result["reason"])
        if result["truncated"]:
            assembled.limits.append("Session candidate limit reached")
        return {"operation": "session", "logon_id": logon.group(1)}, assembled.output({})
    if re.search(r"\bword\b", lower) and "powershell" in lower:
        result = select(db, "c.kind='process' AND (lower(e.parent_process_name)=? OR lower(e.parent_process_name) LIKE ?) AND (lower(e.process_name)=? OR lower(e.process_name) LIKE ?)",
                        ("winword.exe", "%\\winword.exe", "powershell.exe", "%\\powershell.exe"), limit=limit)
        return {"operation": "office_powershell_context", "notes": ["Matches reported parent fields; only evidenced tree links establish parent record identity", "First matching event anchors bounded temporal expansion; prior events are context, not an asserted sequence"]}, enrich_result(db, result)
    if re.search(r"\bdetections?\b", lower):
        assembled = Assembly(db, 500)
        result = detections(db, limit=limit)
        assembled.add_detections(result)
        return {"operation": "detections"}, assembled.output({})
    if re.search(r"\bprocess[- ]tree\b", lower):
        if not stamps:
            raise ValueError("Process-tree questions need an evidence ID or a full timestamp and process name")
        process = re.search(r"\b([\w.-]+\.exe)\b", question, re.I)
        name = process.group(1) if process else "powershell.exe" if "powershell" in lower else None
        if not name:
            raise ValueError("Specify a process name such as powershell.exe")
        result = queries.timeline_around(stamps[0], process=name, artifact_types=["process"], limit=limit)
        if result.total != 1:
            raise ValueError("Process-tree question has no unique anchor; use an evidence ID")
        return {"operation": "process_tree", "process": name}, investigate(db, result.records[0]["id"])
    from forensic_assistant.retrieval.evidence import EvidenceQueries
    plan = plan_question(question, EvidenceQueries(db), date_hint)
    result = plan.execute(EvidenceQueries(db), limit)
    return plan.as_dict(), enrich_result(db, result)
