"""Local autonomous preflight; never probes a provider or grants disclosure."""
from . import readiness
from .provider_diagnostics import REASONS, ALIASES, STAGES


class InvestigationPreflightError(ValueError):
    def __init__(self, diagnostic):
        self.diagnostic=diagnostic
        super().__init__('Investigation not started\n'+ '\n'.join(
            label+': '+str(diagnostic[key]) for key,label in (
                ('category','Category'),('stage','Stage'),('provider','Provider'),('model','Model'),
                ('reason','Reason'),('suggested_action','Suggested action'))))


def require(config, *, provider=None, model=None):
    from .backend import redact
    from forensic_assistant.retrieval.presentation import safe_text
    provider=provider or config.get('provider')
    model=model or config.get('model','not configured')
    public_model=safe_text(redact(str(model)))[:128]
    def fail(category,reason,action,*,origin='local',prior_stage=None):
        diagnostic=dict(category=category,stage='investigation_preflight',provider='OpenAI' if provider=='openai' else 'Other/unconfigured',
            model=public_model,reason=reason,suggested_action=action,origin=origin,
            investigation_started=False,provider_requests=0,evidence_lookups=0,findings=[])
        if prior_stage in STAGES:diagnostic['prior_diagnostic_stage']=prior_stage
        from forensic_assistant import activity
        activity.event('INVESTIGATION_PREFLIGHT','failure',required=True,diagnostic=diagnostic)
        raise InvestigationPreflightError(diagnostic)
    action='Run ai check --full in this same Locard session, explicitly approve the synthetic diagnostic, then retry investigation run only if investigation compatibility is ready.'
    if provider!='openai' or not config.get('cloud_acknowledged'):
        fail('investigation_configuration_required','Autonomous mode requires an explicitly acknowledged OpenAI configuration.','Review ai status and ai configure; no model was substituted.')
    try:
        status=readiness.status(config)
    except (ValueError,KeyError,TypeError,OSError):
        fail('compatibility_check_failed','Local compatibility-state inspection failed.','Review ai status and ai logs; correct the configuration before retrying.')
    if not isinstance(status,dict):
        fail('compatibility_check_failed','Local compatibility state has an invalid structure.','Review ai logs and configuration before retrying.')
    if status.get('investigation_compatibility')=='ready':return
    try:
        quick=readiness.check(config)
        if not isinstance(quick,dict):raise ValueError()
    except (ValueError,KeyError,TypeError,OSError):
        fail('compatibility_check_failed','Local configuration inspection failed.','Review ai status and ai logs before retrying.')
    if quick.get('readiness_category') in ('missing_key','missing_dependency','invalid_configuration'):
        category=quick['readiness_category']
        reasons={'missing_key':'OpenAI credential is not configured.', 'missing_dependency':'Required AI integration dependencies are unavailable.', 'invalid_configuration':'Provider configuration is invalid.'}
        fail(category,reasons[category],'Review ai status and correct the local configuration, then '+action)
    category=ALIASES.get(status.get('readiness_category'),status.get('readiness_category'))
    if category in REASONS and category!='ready':
        fail(category,REASONS[category]+' (recorded by the earlier diagnostic; no new request was sent).',
             'Review ai logs for sanitized provider diagnostics. Resolve the reported condition, then '+action,
             origin='cached_diagnostic',prior_stage=status.get('readiness_stage'))
    fail('investigation_compatibility_unverified','No successful investigation compatibility result is cached for this configuration and credential in this process. Configured is not verified.',action)
