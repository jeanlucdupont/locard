"""Closed diagnostic vocabulary. Never serialize exception text or evidence."""

CODES = ('CURRENT_RECORD_NOT_DISCLOSED', 'PROMPT_BUDGET_EXHAUSTED',
         'EVIDENCE_PACKET_VALIDATION_FAILED', 'WORKER_FAILURE', 'PROVIDER_FAILURE',
         'INTERNAL_FAILURE', 'AUDIT_OR_PERSISTENCE_FAILURE',
         'AUTHORIZATION_EXPIRED', 'AUTHORIZATION_CASE_CHANGED', 'ADDITIONAL_SCOPE_REQUIRED',
         'PROVIDER_SCOPE_CHANGED', 'RESOURCE_BUDGET_EXHAUSTED', 'READ_VIEW_INCONSISTENT')
PHASES = ('startup', 'authorization', 'authorization_persistence', 'worker_retrieval', 'result_validation',
          'result_persistence', 'state_ingest', 'seed_selection', 'packet_preparation',
          'exposure_persistence', 'disclosure_validation', 'provider', 'analysis_persistence', 'analysis_validation',
          'finalization')
COUNTS = ('retrieved_records', 'accepted_batches', 'model_attempts', 'tool_calls', 'prompt_byte_limit')
LABELS = dict(CURRENT_RECORD_NOT_DISCLOSED='Required current evidence has no eligible disclosure fields',
    PROMPT_BUDGET_EXHAUSTED='Required evidence cannot fit the disclosure budget',
    EVIDENCE_PACKET_VALIDATION_FAILED='Evidence disclosure validation failed',
    WORKER_FAILURE='Evidence worker failed', INTERNAL_FAILURE='Unexpected internal investigation failure',
    AUDIT_OR_PERSISTENCE_FAILURE='Required audit or investigation persistence failed')


class PacketFailure(ValueError):
    def __init__(self, code):
        if code not in CODES[:3]:raise ValueError('Invalid packet failure code')
        super().__init__(code)
        self.code = code


def classify(exc, phase):
    from .runner import WorkerError
    from forensic_assistant.llm.client import LLMError
    if isinstance(exc, PacketFailure):return exc.code
    if isinstance(exc, WorkerError):return 'WORKER_FAILURE'
    # Only exact application-defined sentinels may become public reasons.
    if type(exc) is ValueError and str(exc) in CODES[7:]:return str(exc)
    if isinstance(exc, LLMError) or phase=='provider':return 'PROVIDER_FAILURE'
    if isinstance(exc, OSError):return 'AUDIT_OR_PERSISTENCE_FAILURE'
    return 'INTERNAL_FAILURE'


def diagnostic(code, phase, operation, state, batches, attempts, *, worker=None):
    value = dict(contract='investigation-failure-v1', code=code, phase=phase,
        operation=operation, retrieved_records=len(state.records), accepted_batches=batches,
        model_attempts=attempts, tool_calls=state.accepted, prompt_byte_limit=state.budget.prompt_bytes)
    if worker is not None:
        from .worker_diagnostics import validate as validate_worker
        validate_worker(worker)
        value['worker']=worker
    validate(value)
    return value


def validate(value):
    if isinstance(value,dict) and 'worker' in value:
        from .worker_diagnostics import validate as validate_worker
        validate_worker(value['worker'])
    if (type(value) is not dict or set(value)-{'worker'}!=set(COUNTS)|{'contract','code','phase','operation'}
            or value['contract']!='investigation-failure-v1' or value['code'] not in CODES
            or value['phase'] not in PHASES or value['operation'] not in ('initial','show_evidence','follow_up','inspect_context')
            or any(type(value[k]) is not int or not 0<=value[k]<=(24576 if k=='prompt_byte_limit' else 5600) for k in COUNTS)):
        raise ValueError('Invalid recorded investigation diagnostic')


def validate_allocation(value, exposure):
    counts={'disclosed_records','compact_observations','compact_interpretations',
            'omitted_candidate_fields','omitted_candidate_records',
            'omitted_candidate_interpretations','prior_support_fields_omitted'}
    if (type(value) is not dict or set(value)!=counts|{'optional_context_omitted'}
            or type(value['optional_context_omitted']) is not bool
            or any(type(value[k]) is not int or not 0<=value[k]<=20000 for k in counts)
            or value['disclosed_records']!=len(exposure['records'])
            or value['compact_observations']!=sum(len(r['observations']) for r in exposure['records'])
            or value['compact_interpretations']!=sum(len(r['interpretations']) for r in exposure['records'])):
        raise ValueError('Invalid recorded allocation diagnostics')
