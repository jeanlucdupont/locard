import json
from forensic_assistant.correlation.investigation import timeline_context
from forensic_assistant.llm.context import context_bundle, annotate_relationship_support
from forensic_assistant.llm.prompts import messages
from forensic_assistant.llm.client import LocalClient


def summary_schema(ids):
    claim = {"type": "object", "additionalProperties": False,
             "properties": {"statement": {"type": "string"},
                            "classification": {"type": "string", "enum": ["OBSERVED", "CORRELATED", "HYPOTHESIS", "UNKNOWN"]},
                            "evidence_ids": {"type": "array", "minItems": 1, "items": {"type": "string", "enum": sorted(ids)}}},
             "required": ["statement", "classification", "evidence_ids"]}
    properties = {key: {"type": "array", "maxItems": 3, "items": claim} for key in
                  ("summary", "observed_sequence", "possible_interpretation", "alternative_explanations")}
    properties.update({key: {"type": "array", "items": {"type": "string"}} for key in ("gaps_missing_evidence", "next_forensic_steps")})
    return {"type": "object", "additionalProperties": False, "properties": properties, "required": list(properties)}


def validate_summary(content, bundle):
    try:
        result = json.loads(content)
    except (TypeError, ValueError) as exc:
        raise ValueError("Timeline analysis was not JSON; analysis withheld") from exc
    ids = {e["id"] for e in bundle["EVIDENCE"]}
    if not isinstance(result, dict) or set(result) != set(summary_schema(ids)["properties"]):
        raise ValueError("Timeline analysis structure invalid; analysis withheld")
    for section in ("summary", "observed_sequence", "possible_interpretation", "alternative_explanations"):
        if not isinstance(result[section], list) or len(result[section]) > 3:
            raise ValueError("Timeline analysis section invalid")
        for claim in result[section]:
            if not isinstance(claim, dict) or set(claim) != {"statement", "classification", "evidence_ids"}:
                raise ValueError("Timeline claim invalid")
            if not isinstance(claim["statement"], str) or not claim["statement"].strip():
                raise ValueError("Timeline claim text missing")
            refs = claim["evidence_ids"]
            if not isinstance(refs, list) or not refs or not all(isinstance(eid, str) and eid in ids for eid in refs):
                raise ValueError("Timeline claim has missing or unknown citations")
            label = claim["classification"]
            if label not in {"OBSERVED", "CORRELATED", "HYPOTHESIS", "UNKNOWN"}:
                raise ValueError("Unknown timeline claim classification")
            if section == "observed_sequence" and label not in ("OBSERVED", "CORRELATED"):
                raise ValueError("A hypothesis cannot appear as an observed sequence")
            if section in ("possible_interpretation", "alternative_explanations") and label not in ("HYPOTHESIS", "UNKNOWN"):
                raise ValueError("Interpretations must be explicitly qualified")
            if label == "CORRELATED" and not any(set(r["evidence_ids"]) <= set(refs) for r in bundle["CORRELATED_EVIDENCE"]):
                raise ValueError("Correlated claim lacks supporting supplied relationship evidence")
    for section in ("gaps_missing_evidence", "next_forensic_steps"):
        if not isinstance(result[section], list) or not all(isinstance(value, str) for value in result[section]):
            raise ValueError("Timeline limitations or next steps are invalid")
    import re
    for ref in re.findall(r"EVTX:[^\s\"\[\],}]+", content):
        if ref.rstrip(".;)") not in ids:
            raise ValueError("Timeline text contains unknown evidence IDs")
    for section in ("summary", "observed_sequence", "possible_interpretation", "alternative_explanations"):
        for claim in result[section]:
            annotate_relationship_support(claim, bundle)
    return result


def analyze_timeline(db, start, end, *, hostname=None, username=None, max_candidates=500,
                     endpoint="http://127.0.0.1:8080", timeout=120, dry_run=False, client=None):
    context = timeline_context(db, start, end, hostname=hostname, username=username, max_candidates=max_candidates)
    question = "Summarize this timeline using summary, observed_sequence, possible_interpretation, alternative_explanations, gaps_missing_evidence, and next_forensic_steps. Classify claims OBSERVED/CORRELATED/HYPOTHESIS/UNKNOWN. Interpretations and alternatives must be HYPOTHESIS or UNKNOWN. Cite every claim. Be concise. Do not infer a complete attack sequence."
    bundle = context_bundle(context, question)
    output = {"evidence_bundle": bundle, "notice": "Model analysis is not evidence. Citation checks do not establish factual correctness."}
    if not bundle["EVIDENCE"]:
        output["status"] = "insufficient_evidence"
    elif dry_run:
        output["status"] = "retrieved_only"
    else:
        client = client or LocalClient(endpoint, timeout)
        content = client.complete(messages(bundle), schema=summary_schema({e["id"] for e in bundle["EVIDENCE"]}))
        output["analysis"] = validate_summary(content, bundle)
        output["status"] = "model_analysis"
    return output
