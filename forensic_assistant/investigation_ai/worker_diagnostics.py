"""Bounded worker failures: application categories only, never exception prose."""
import sqlite3
import json
from contextlib import contextmanager
from .diagnostics import PHASES

CATEGORIES = ('SQLITE_QUERY_DEADLINE','PARENT_WORKER_TIMEOUT','WORKER_UNAVAILABLE',
              'SEARCH_AUTHORIZATION_REJECTED','DATABASE_READ_VIEW_FAILURE',
              'WORKER_PROTOCOL_ERROR','WORKER_INTERNAL_ERROR','SEARCH_DATA_VALIDATION_FAILURE')

LOCATIONS = ('WORKER_OPERATION','SEARCH_EXECUTION','ANCHOR_RESOLUTION','WORKER_AUTHORIZATION','SEARCH_DEDUPLICATION',
             'TIMESTAMP_QUERY','CANDIDATE_ORDERING','SOURCE_SCOPE_VALIDATION','EVIDENCE_HYDRATION',
             'EVIDENCE_PROJECTION','SEARCH_RESULT_VALIDATION','PROGRESS_HANDLER_SETUP',
             'PROGRESS_HANDLER_RESTORATION','WORKER_RESPONSE_SERIALIZATION','WORKER_RESPONSE_VALIDATION')
EXCEPTIONS = {ValueError:'ValueError', KeyError:'KeyError', TypeError:'TypeError', IndexError:'IndexError',
              RuntimeError:'RuntimeError', OverflowError:'OverflowError', json.JSONDecodeError:'JSONDecodeError',
              sqlite3.OperationalError:'sqlite3.OperationalError', sqlite3.DatabaseError:'sqlite3.DatabaseError'}
COUNTS = {'candidates_fetched':1000,'candidates_examined':1000,'source_excluded':1000,'records_projected':3}


class Trace:
    """Per-operation content-free location and counters; never evidence authority."""
    def __init__(self):
        self.location='WORKER_OPERATION'
        self.counts=dict.fromkeys(COUNTS,0)

    @contextmanager
    def at(self, location):
        if location not in LOCATIONS:raise ValueError('Invalid worker location')
        self.location=location
        try:yield
        except Exception as exc:
            # Preserve the originating location through successful finally cleanup.
            if not hasattr(exc,'_locard_failure_location'):
                exc._locard_failure_location=location
                exc._locard_failure_counts=dict(self.counts)
            raise


def detail(category, phase=None, exceeded=False):
    value=dict(contract='worker-failure-v1',category=category,
               phase=phase if phase in PHASES else 'tool',deadline_exceeded=bool(exceeded))
    validate(value)
    return value


def validate(value):
    base={'contract','category','phase','deadline_exceeded'}
    extra={'location','exception_class','counts'}
    if (type(value) is not dict or value.get('contract') not in ('worker-failure-v1','worker-failure-v2')
        or set(value)!=(base|extra if value['contract']=='worker-failure-v2' else base)
        or value['category'] not in CATEGORIES
        or type(value['phase']) is not str or value['phase'] not in PHASES or type(value['deadline_exceeded']) is not bool):
        raise ValueError('Invalid worker failure diagnostic')
    if value['contract']=='worker-failure-v2':
        if (value['location'] not in LOCATIONS or value['exception_class'] not in (*EXCEPTIONS.values(),'Other')
            or type(value['counts']) is not dict or set(value['counts'])!=set(COUNTS)
            or any(type(value['counts'][k]) is not int or not 0<=value['counts'][k]<=cap for k,cap in COUNTS.items())):
            raise ValueError('Invalid worker failure diagnostic')


def classify(exc, phase, exceeded, trace=None):
    if isinstance(exc,sqlite3.Error):
        category='SQLITE_QUERY_DEADLINE' if getattr(exc,'sqlite_errorcode',None)==sqlite3.SQLITE_INTERRUPT and exceeded else 'DATABASE_READ_VIEW_FAILURE'
    elif isinstance(exc,OSError) or str(exc).startswith('EVIDENCE_STATE_CHANGED'):
        category='DATABASE_READ_VIEW_FAILURE'
    elif type(exc) is ValueError and str(exc) in ('ADDITIONAL_SCOPE_REQUIRED','AUTHORIZATION_INVALID','AUTHORIZATION_EXPIRED','AUTHORIZATION_CASE_CHANGED','FOLLOW_UP_BUDGET_OR_DUPLICATE','FOLLOW_UP_ANCHOR_NOT_RETRIEVED','FOLLOW_UP_ANCHOR_OUTSIDE_WINDOW','RESOURCE_BUDGET_EXHAUSTED','CONTEXT_DUPLICATE'):
        category='SEARCH_AUTHORIZATION_REJECTED'
    else:category='WORKER_INTERNAL_ERROR'
    if type(exc) is json.JSONDecodeError:category='SEARCH_DATA_VALIDATION_FAILURE'
    location=getattr(exc,'_locard_failure_location',trace.location if trace else 'WORKER_OPERATION')
    if type(exc) is ValueError and str(exc) in (
        'Use a full ISO timestamp with Z or an explicit UTC offset',
        'Invalid follow-up source/family','Invalid follow-up scope','Invalid follow-up identities',
        'Follow-up eligibility timestamp not retained','Evidence ID not found'):
        category='SEARCH_DATA_VALIDATION_FAILURE'
    value=detail(category,phase,exceeded)
    if trace is not None:
        value.update(contract='worker-failure-v2',location=location,
                     exception_class=EXCEPTIONS.get(type(exc),'Other'),
                     counts=dict(getattr(exc,'_locard_failure_counts',trace.counts)))
        validate(value)
    return value


def protocol_detail(phase):
    value=detail('WORKER_PROTOCOL_ERROR',phase)
    value.update(contract='worker-failure-v2',location='WORKER_RESPONSE_VALIDATION',
                 exception_class='Other',counts=dict.fromkeys(COUNTS,0))
    validate(value)
    return value
