"""Explicit cloud request modes; no model-name guesses or runtime fallback."""
from dataclasses import dataclass
import copy
import json


@dataclass(frozen=True)
class Capability:
    route: str
    mode: str
    supports_json_schema: bool
    supports_json_object: bool
    supports_plain_json_instruction: bool = True


CAPABILITIES = {
    "openai": Capability("openai", "json_schema", True, True),
    "anthropic": Capability("anthropic", "anthropic_schema", True, False),
    "gemini": Capability("gemini", "gemini_schema", True, True),
    "deepseek": Capability("deepseek", "json_object", False, True),
    "xai": Capability("xai", "json_schema", True, True),
}


def configure(kwargs, provider, schema):
    capability = CAPABILITIES[provider]
    schema = copy.deepcopy(schema if schema is not None else {"type": "object"})
    from .openai_schema import investigation, request_schema, instruct
    adapted = provider == 'openai' and investigation(schema)
    if adapted:
        schema = request_schema(provider, schema)
        kwargs['messages'] = instruct(kwargs['messages'])
    if capability.mode == "json_schema":
        kwargs["response_format"] = {"type": "json_schema", "json_schema": {
            "name": "investigation_proposal" if adapted else "forensic_analysis", "strict": True, "schema": schema}}
    elif capability.mode == "anthropic_schema":
        # Use the independently validated LiteLLM Anthropic JSON-schema route.
        kwargs["response_format"] = {"type": "json_schema", "json_schema": {"name": "forensic_analysis", "strict": True, "schema": schema}}
    elif capability.mode == "gemini_schema":
        # Direct JSON Schema native parameter avoids the legacy OpenAPI converter.
        kwargs["response_mime_type"] = "application/json"
        kwargs["response_json_schema"] = schema
    elif capability.mode == "json_object":
        kwargs["response_format"] = {"type": "json_object"}
        kwargs["messages"] = [
            {"role": "system", "content": "Return only a JSON object satisfying this exact JSON Schema. "
             "Do not add markdown or prose. Schema: " + json.dumps(schema, ensure_ascii=True)},
            *copy.deepcopy(kwargs["messages"]),
        ]
    else:
        raise ValueError("Unsupported structured mode")
    return kwargs


# Explicit strategy selection; generic controller and other providers stay unchanged.
INVESTIGATION_STRATEGIES = {'anthropic': 'two_stage_tool_schema'}
