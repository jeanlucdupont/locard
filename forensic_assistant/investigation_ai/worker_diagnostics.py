"""Bounded worker failures: application categories only, never exception prose."""
import sqlite3
from .diagnostics import PHASES

CATEGORIES = ('SQLITE_QUERY_DEADLINE','PARENT_WORKER_TIMEOUT','WORKER_UNAVAILABLE',
              'SEARCH_AUTHORIZATION_REJECTED','DATABASE_READ_VIEW_FAILURE',
              'WORKER_PROTOCOL_ERROR','WORKER_INTERNAL_ERROR')


def detail(category, phase=None, exceeded=False):
    value=dict(contract='worker-failure-v1',category=category,
               phase=phase if phase in PHASES else 'tool',deadline_exceeded=bool(exceeded))
    validate(value)
    return value


def validate(value):
    if (type(value) is not dict or set(value)!={'contract','category','phase','deadline_exceeded'}
        or value['contract']!='worker-failure-v1' or value['category'] not in CATEGORIES
        or value['phase'] not in PHASES or type(value['deadline_exceeded']) is not bool):
        raise ValueError('Invalid worker failure diagnostic')


def classify(exc, phase, exceeded):
    if isinstance(exc,sqlite3.Error):
        category='SQLITE_QUERY_DEADLINE' if getattr(exc,'sqlite_errorcode',None)==sqlite3.SQLITE_INTERRUPT and exceeded else 'DATABASE_READ_VIEW_FAILURE'
    elif isinstance(exc,OSError) or str(exc).startswith('EVIDENCE_STATE_CHANGED'):
        category='DATABASE_READ_VIEW_FAILURE'
    elif type(exc) is ValueError and str(exc) in ('ADDITIONAL_SCOPE_REQUIRED','AUTHORIZATION_INVALID','AUTHORIZATION_EXPIRED','AUTHORIZATION_CASE_CHANGED','FOLLOW_UP_BUDGET_OR_DUPLICATE','FOLLOW_UP_ANCHOR_NOT_RETRIEVED','FOLLOW_UP_ANCHOR_OUTSIDE_WINDOW','RESOURCE_BUDGET_EXHAUSTED','CONTEXT_DUPLICATE'):
        category='SEARCH_AUTHORIZATION_REJECTED'
    else:category='WORKER_INTERNAL_ERROR'
    return detail(category,phase,exceeded)
