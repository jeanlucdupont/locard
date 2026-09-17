from forensic_assistant.llm.client import LocalClient
from forensic_assistant.llm.prompts import messages, validate_answer, answer_schema
from forensic_assistant.retrieval.v1_planner import retrieve_question
from forensic_assistant.llm.context import context_bundle, annotate_relationship_support


def ask(queries, question, *, endpoint="http://127.0.0.1:8080", date_hint=None,
        limit=30, dry_run=False, timeout=120, client=None):
    plan, context = retrieve_question(queries, question, date_hint, limit)
    bundle = context_bundle(context, question)
    output = {"plan": plan, "evidence_bundle": bundle,
              "notice": "Model analysis is not evidence. Citation checks verify references, not factual correctness; validate claims against the original records."}
    if not bundle["EVIDENCE"]:
        output["status"] = "insufficient_evidence"
        output["message"] = "No matching records in the supplied evidence. This does not establish absence of activity."
    elif dry_run:
        output["status"] = "retrieved_only"
    else:
        client = client or LocalClient(endpoint, timeout)
        supplied_ids = {e["id"] for e in bundle["EVIDENCE"]}
        content = client.complete(messages(bundle), schema=answer_schema(supplied_ids))
        output["analysis"] = validate_answer(content, supplied_ids)
        for finding in output["analysis"]["findings"]:
            annotate_relationship_support(finding, bundle, "finding")
        output["status"] = "model_analysis"
    return output
