from forensic_assistant.retrieval.planner import plan_question
from forensic_assistant.llm.client import LocalClient
from forensic_assistant.llm.prompts import evidence_bundle, messages, validate_answer, answer_schema


def ask(queries, question, *, endpoint="http://127.0.0.1:8080", date_hint=None,
        limit=30, dry_run=False, timeout=120, client=None):
    plan = plan_question(question, queries, date_hint)
    result = plan.execute(queries, limit)
    coverage = queries.coverage()
    compact_coverage = {"events_without_utc": coverage["events_without_utc"],
                        "incomplete_ingestion_runs": sum(r["status"] != "complete" for r in coverage["ingestion_runs"])}
    bundle = evidence_bundle(result, question, compact_coverage)
    output = {"plan": plan.as_dict(), "evidence_bundle": bundle,
              "notice": "Model analysis is not evidence. Citation checks verify references, not factual correctness; validate claims against the original records."}
    if not result.records:
        output["status"] = "insufficient_evidence"
        output["message"] = "No matching records in the supplied evidence. This does not establish absence of activity."
    elif dry_run:
        output["status"] = "retrieved_only"
    else:
        client = client or LocalClient(endpoint, timeout)
        supplied_ids = {e["id"] for e in bundle["EVIDENCE"]}
        content = client.complete(messages(bundle), schema=answer_schema(supplied_ids))
        output["analysis"] = validate_answer(content, supplied_ids)
        output["status"] = "model_analysis"
    return output
