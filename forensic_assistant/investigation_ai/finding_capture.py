"""Trusted parent integration: provider approval and saving are separate decisions."""
from copy import deepcopy
import sqlite3

from . import d2_execution
from .findings import Workspace, _text


class Capture:
    """One session over an existing workspace; never creates or authorizes anything."""
    def __init__(self, prepared, directory):
        if type(prepared) is not d2_execution.Prepared:
            raise ValueError('CAPTURE_PREPARED_REQUIRED')
        prepared.check()
        if prepared.profile not in ('d2q1', 'd2x1'):
            raise ValueError('CAPTURE_QUALITY_PROFILE_REQUIRED')
        self.prepared = prepared
        self.seal = prepared.identity()
        self.workspace = Workspace(directory)
        self.workspace_id = None
        self.done = False
        self._inspect()  # Before provider authorization, including source reconstruction.

    def _inspect(self):
        self.prepared.check()
        if self.prepared.identity() != self.seal:
            raise ValueError('CAPTURE_REQUEST_CHANGED')
        state = self.workspace.export()
        metadata = state['metadata']
        packet = self.prepared.packet['content']
        if (state['source_binding_status'] != 'valid_recorded_binding' or
                metadata['binding'] != dict(source=packet['source'], view=packet['view']) or
                (self.workspace_id is not None and metadata['id'] != self.workspace_id)):
            raise ValueError('CAPTURE_WORKSPACE_BINDING')
        self.workspace_id = metadata['id']
        return state

    def finish(self, result, confirmation, *, actor):
        """Consume existing parent result only; no dispatch, authorization or lookup."""
        if self.done:
            return dict(status='already_handled', finding_ids=[])
        self.done = True
        if result.get('status') != 'accepted' or 'validated' not in result:
            return dict(status='not_eligible', finding_ids=[])
        writing = False
        try:
            validated = deepcopy(result['validated'])
            # Validate before offering registration; raw or corrupted result objects
            # cannot turn a status flag into authority. Import repeats this at write.
            self.workspace._validated_result_text(self.prepared, validated)
            count = len(validated['proposals'])
            if not count:
                return dict(status='no_inferential_findings', finding_ids=[])
            self.workspace._capture_indices(validated)
            state = self._inspect()
            offer = dict(workspace_id=self.workspace_id, directory=str(self.workspace.directory),
                         revision=state['revision'], count=count, state='proposed', origin='ai_proposal',
                         classification='unverified', actor_authority='locally asserted')
            if not callable(confirmation) or confirmation(deepcopy(offer)) is not True:
                return dict(status='declined', finding_ids=[], revision=state['revision'])
            writing = True
            identities = self.workspace.import_results(self.prepared, validated, actor=actor,
                expected_revision=state['revision'], expected_workspace_id=self.workspace_id)
            return dict(status='captured', workspace_id=self.workspace_id, finding_ids=identities,
                        revision=state['revision'] + len(identities), state='proposed', origin='ai_proposal')
        except (KeyboardInterrupt, EOFError):
            return dict(status='storage_uncertain' if writing else 'cancelled', finding_ids=[])
        except (OSError, sqlite3.Error):
            return dict(status='storage_uncertain', finding_ids=[], reason='inspect_workspace_before_retry')
        except (ValueError, KeyError, TypeError) as exc:
            code = str(exc)
            status = ('conflict' if code == 'FINDINGS_STALE_REVISION' else
                      'already_captured' if code == 'FINDINGS_ALREADY_CAPTURED' else
                      'duplicate_accounts' if code == 'FINDINGS_DUPLICATE_ACCOUNTS' else 'failed')
            return dict(status=status, finding_ids=[], reason='capture_not_committed')


def run(prepared, provider_confirmation, *, directory, actor, capture_confirmation, display):
    """Reusable parent orchestration. No special provider or worker path."""
    _text(actor, 256)
    capture = Capture(prepared, directory)
    result = d2_execution.execute(d2_execution.authorize(prepared, provider_confirmation))
    display(result, prepared)
    decision = capture.finish(result, capture_confirmation, actor=actor)
    return dict(result=result, capture=decision)
