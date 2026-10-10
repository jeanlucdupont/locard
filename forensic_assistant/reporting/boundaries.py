"""Approved report boundaries, not evidence claims or investigative negatives."""
from .view_v2 import CAUTIONS, kind


def approved(data):
    """Compute permissions from report state, never from model prose."""
    result = []
    if any(kind(record) == 'mft' for record in data['evidence'].values()):
        result.append({'boundary_id': 'mft_metadata_boundary', 'text': CAUTIONS['mft']})
    if not any(c['category'] in ('DETERMINISTIC RELATIONSHIP', 'CORROBORATED RELATIONSHIP')
               for c in data['claims']):
        result.append({'boundary_id': 'no_relationship_asserted',
                       'text': 'No relationship between the selected records is asserted by this report.'})
    return result
