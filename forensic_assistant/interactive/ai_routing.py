"""Conservative routing of explicit case-fact questions; uncertainty stays advisory."""
import re
from .advisory import is_inventory_question, asks_about_metadata


def needs_investigation(request):
    if not isinstance(request, str) or len(request) > 4000:
        return False
    if is_inventory_question(request) or asks_about_metadata(request):
        return False
    # Require both a concrete file/record reference and an explicit factual query.
    # General guidance, inventory and ambiguous conversational requests stay advisory.
    text = request.strip()
    reference = re.search(r'\b(?:[\w.-]+\.(?:exe|dll|zip|ps1|bat|cmd|pdf|docx?|xlsx?)\b|(?:EVTX|MFT|PREFETCH|REGISTRY|BROWSER):[a-f0-9]{64}:)', text, re.I)
    question = re.match(r'^(?:did|was|were|has|have|when did|when was|which records|show evidence for|inspect evidence for)\b', text, re.I)
    return bool(reference and question)
