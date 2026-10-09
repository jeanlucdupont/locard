"""Separate intentional shutdown decoration from command output assertions."""
from forensic_assistant.cli import get_liner


def before_shutdown(text):
    marker = get_liner() + '\n\nLocard session ended.\n'
    assert text.count(marker) == 1
    return text.split(marker, 1)[0]
