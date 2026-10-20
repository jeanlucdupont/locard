"""Cloud-only canonical validation. Never resolve external schema resources."""
import json
from .provider_diagnostics import ProviderFailure


def validator(schema):
    try:
        from jsonschema import Draft202012Validator
        from referencing import Registry
    except ImportError:
        raise ProviderFailure("missing_dependency", "configuration") from None
    def deny(uri):
        from referencing.exceptions import NoSuchResource
        raise NoSuchResource(ref=uri)
    schema = schema if schema is not None else {"type": "object"}
    try:
        Draft202012Validator.check_schema(schema)
        return Draft202012Validator(schema, registry=Registry(retrieve=deny))
    except Exception:
        raise ProviderFailure("structured_validation", "structured_validation") from None


def validate(text, schema, *, diagnostic_phase="canonical"):
    contract = validator(schema)
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError()
            result[key] = value
        return result
    def invalid(value):
        raise ValueError()
    try:
        if not isinstance(text, str) or len(text.encode("utf-8")) > 1024 * 1024:
            raise ValueError()
        value = json.loads(text, object_pairs_hook=pairs, parse_constant=invalid)
    except (ValueError, TypeError, RecursionError):
        raise ProviderFailure("response_parse", "response_parse") from None
    try:
        contract.validate(value)
    except Exception:
        from .validation_diagnostics import extract
        try: detail = extract(contract,value,diagnostic_phase)
        except Exception: detail = {'phase':diagnostic_phase}
        raise ProviderFailure("structured_validation", "structured_validation",
                              metadata={'validation_diagnostics':detail}) from None
    return value
