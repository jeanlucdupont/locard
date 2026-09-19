"""Prioritized bounded bundles; relationships travel with all supporting records."""
import hashlib
import json
from forensic_assistant.llm.prompts import SYSTEM_PROMPT, PROMPT_BYTES, FIELDS


def compact_record(event):
    if event.get('source_type') not in (None,'evtx'):
        from forensic_assistant.llm.artifact_fields import compact_artifact
        return compact_artifact(event)
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
    if event.get('source_type'):
        result['source_type']='evtx'
        result['timestamp_type']='EVTX SystemTime'
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
    classes=('evtx','mft','prefetch','registry')
    distribution=context.get('artifact_distribution',{kind:sum(e['id'].startswith(kind.upper()+':') for e in records.values()) for kind in classes})
    metadata['artifact_distribution']={kind:{'candidate':distribution.get(kind,0),'selected':0,'omitted':distribution.get(kind,0)} for kind in classes}
    metadata['omitted_artifact_classes']=[]
    bundle = {"metadata": metadata, "EVIDENCE": [], "DIRECT_EVIDENCE": [],
              "CORRELATED_EVIDENCE": [], "DETECTIONS": [], "UNRESOLVED_RELATIONSHIPS": [], "QUESTION": question}
    sent = set()

    def update():
        metadata["sent_records"] = len(sent)
        metadata["omitted_records"] = context["candidate_count"] - len(sent)
        metadata["fields_truncated"] = any(e.get("truncated_fields") for e in bundle["EVIDENCE"])
        for kind,item in metadata['artifact_distribution'].items():
            item['selected']=sum(eid.startswith(kind.upper()+':') for eid in sent)
            item['omitted']=item['candidate']-item['selected']
        metadata['omitted_artifact_classes']=[kind for kind,item in metadata['artifact_distribution'].items() if item['candidate'] and not item['selected']]

    def fits():
        return len(SYSTEM_PROMPT.encode()) + len(json.dumps(bundle, ensure_ascii=True).encode()) <= budget

    def package(ids, section=None, item=None):
        ids=list(ids)
        for eid in list(ids):
            ids.extend(records.get(eid,{}).get('supporting_evidence_ids',[]))
        if not set(ids) <= records.keys():
            return False
        new = [eid for eid in dict.fromkeys(ids) if eid not in sent]
        old_length = len(bundle["EVIDENCE"])
        bundle["EVIDENCE"].extend(compact_record(records[eid]) for eid in new)
        if context.get('semantic_retrieval'):
            for item in bundle['EVIDENCE'][old_length:]:
                item['selection_reasons']=context.get('selection_reasons',{}).get(item['id'],['deterministic_expansion'])
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
    def relationship_rank(relation):
        if relation['relationship']!='cross_artifact_observation':return 0
        if relation.get('matched_fields',{}).get('exact_paths'):return 1
        if relation['status']=='CORROBORATED':return 2
        return 3
    ordered_relations=sorted(context['correlated_evidence'],key=relationship_rank)
    def pack_relationship(relation):
        slim = {key: relation[key] for key in ("relationship", "status", "evidence_ids", "reason", "limitations")}
        slim["relationship_id"] = "REL:" + hashlib.sha256(json.dumps(slim, sort_keys=True).encode()).hexdigest()[:16]
        if not package(slim["evidence_ids"], "CORRELATED_EVIDENCE", slim):
            metadata["omitted_relationships"] += 1
    for relation in ordered_relations:
        if relationship_rank(relation)<3:pack_relationship(relation)
    for detection in context["detections"]:
        slim = {key: detection[key] for key in ("rule_id", "rule_name", "rule_version", "severity", "evidence_ids", "reason", "limitations")}
        if not package(slim["evidence_ids"], "DETECTIONS", slim):
            metadata["omitted_detections"] += 1
    for group in ("correlated", "exact_objects", "corroboration", "detections", "semantic", "temporal", "other"):
        ids=context['priorities'].get(group,[])
        if context.get('semantic_retrieval') and group in ('semantic','temporal','other'):
            # Round-robin only within weaker tiers; exact evidence keeps priority.
            queues=[[eid for eid in ids if eid.startswith(kind.upper()+':')] for kind in classes]
            ids=[q[i] for i in range(max(map(len,queues),default=0)) for q in queues if i<len(q)]
        for eid in ids:
            package([eid])
    for relation in ordered_relations:
        if relationship_rank(relation)==3:pack_relationship(relation)
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
        order=['UNRESOLVED','POSSIBLE','LIKELY','CORROBORATED','CONFIRMED']
        claim['correlation_status']=min((r['status'] for r in supporting),key=order.index)
        if claim.get('classification') in ('CORRELATED','CORROBORATED') and claim['correlation_status']!='CONFIRMED':
            claim[text_field]=claim['correlation_status']+' relationship (deterministic assessment): '+claim[text_field]
    return claim
