"""Bounded observations, never completion/grounding authority."""
import math
import time


def observed(client, started):
    metadata = getattr(client, 'last_metadata', {})
    metadata = metadata if isinstance(metadata, dict) else {}
    finish = metadata.get('finish_reason')
    finish = finish if finish in ('stop', 'end_turn', 'length', 'content_filter',
                                 'tool_calls', 'function_call') else None
    elapsed = time.monotonic() - started
    return {'observer': 'controller', 'backend_response_received': True,
            'finish_reason': finish,
            'completion_status': 'reported' if finish else 'unavailable',
            'elapsed_seconds': round(max(0, elapsed), 6) if math.isfinite(elapsed) else None,
            'parent_cleanup_confirmation': 'not_observed_here'}
