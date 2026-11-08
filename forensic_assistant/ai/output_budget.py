"""Controller-owned output allowance; independent of input and time budgets."""
from contextlib import contextmanager
from contextvars import ContextVar

ORDINARY_OUTPUT_TOKENS = 1024
FINAL_OUTPUT_TOKENS = 4096
FINAL_ONLY = ContextVar('final_only_output', default=False)


def output_tokens():
    return FINAL_OUTPUT_TOKENS if FINAL_ONLY.get() else ORDINARY_OUTPUT_TOKENS


@contextmanager
def final_output(enabled):
    token = FINAL_ONLY.set(enabled is True)
    try:
        yield
    finally:
        FINAL_ONLY.reset(token)
