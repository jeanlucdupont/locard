from forensic_assistant.llm.client import LocalClient
from forensic_assistant.llm.prompts import messages, validate_answer, answer_schema
from forensic_assistant.llm.context import context_bundle, annotate_relationship_support


def ask(
    queries,
    question,
    *,
    endpoint="http://127.0.0.1:8080",
    date_hint=None,
    limit=30,
    dry_run=False,
    timeout=120,
    client=None,
    semantic_index=None,
    embedding_model=None,
    semantic_options=None
):
    from argparse import Namespace
    from forensic_assistant.semantic.hybrid import retrieve
    from forensic_assistant.semantic.index import default_root
    db_path = queries.db.execute('PRAGMA database_list').fetchone()[2]
    root = semantic_index or (default_root(db_path) if db_path else None)
    def prepare():
        from forensic_assistant.semantic.cli import prepare as prepare_semantic
        options = vars(semantic_options).copy() if semantic_options is not None else {'json': True}
        options.update(db=db_path, index=semantic_index, model_path=embedding_model, semantic_command='search')
        resolved_root, model, _ = prepare_semantic(queries.db, Namespace(**options))
        return resolved_root, model
    plan, context = retrieve(queries, question, date_hint, limit, index_root=root,
                             prepare=prepare if root is not None else None)
    bundle = context_bundle(context, question)
    from forensic_assistant.llm.grounding import assess
    grounding = assess(bundle, plan)
    output = {
        "plan": plan,
        "evidence_bundle": bundle,
        "grounding": grounding,
        "notice": "Model analysis is not evidence. Citation checks verify references, not factual correctness; validate claims against the original records. Confidence is model assessment metadata, not forensic certainty."
    }
    if not bundle["EVIDENCE"]:
        output["status"] = "insufficient_evidence"
        output["message"] = "No matching records in the supplied evidence. This does not establish absence of activity."
    elif dry_run:
        output["status"] = "retrieved_only"
    elif grounding['withhold_model_analysis']:
        # Retain the evidence/candidate records, but do not solicit unsupported
        # activity findings from an artifact incapable of establishing them.
        output['status'] = 'insufficient_evidence'
        output['message'] = grounding['statement']
    else:
        client = client or LocalClient(endpoint, timeout)
        supplied_ids = {e["id"] for e in bundle["EVIDENCE"]}
        content = client.complete(messages(bundle), schema=answer_schema(supplied_ids))
        output["analysis"] = validate_answer(content, supplied_ids)
        for finding in output["analysis"]["findings"]:
            annotate_relationship_support(finding, bundle, "finding")
        output["status"] = "model_analysis"
    return output
