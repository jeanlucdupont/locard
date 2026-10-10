"""Separate intentional shutdown decoration from command output assertions."""


def before_shutdown(text):
    marker = '\nLocard session ended.\n'
    assert text.count(marker) == 1
    return text.split(marker, 1)[0]
