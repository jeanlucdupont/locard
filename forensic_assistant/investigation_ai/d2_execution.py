"""Ephemeral, one-grant D2 application service. No case, journal or tool access."""
from copy import deepcopy
import hashlib
import json
import multiprocessing
import os
import queue
import threading
import time

from . import d2, d2_wire as wire, d2_contracts
from .transcript import digest
from .supervision import Launch, _stop
from .lifecycle import WorkerJob, CleanupError

LIMITS = dict(attempts=1, rounds=1, body_bytes=5600, output_tokens=1024,
              seconds=60, cleanup_seconds=5, lookups=0, retries=0)
GRANT = 'd2-reasoning-authorization-v1'


class Prepared:
    """Created from trusted history; serialized caller packets are not an import API."""
    def __init__(self, history, packet, config, options):
        if config['provider'] != 'openai':
            raise ValueError('D2_OPENAI_REQUIRED')
        self.history, self.packet, self.config, self.options = history, deepcopy(packet), deepcopy(config), deepcopy(options)
        self.messages = wire.messages(self.packet)
        wire.expand_view(json.loads(self.messages[1]['content']), self.packet)
        self.body = wire.body(self.messages, config['model'])
        self._seal = self.identity()
        self.check()

    def identity(self):
        return digest(dict(packet=self.packet, messages=self.messages, body=self.body.hex(),
                           config=self.config, options=self.options, limits=LIMITS))

    def check(self):
        if self.identity() != self._seal:
            raise ValueError('D2_PREPARED_CHANGED')
        wire.expand_view(json.loads(self.messages[1]['content']), self.packet)
        # A no-item canonical proposal validates original packet authority without AI.
        self.history.validate(self.packet, wire.J(dict(contract=d2_contracts.RESPONSE,
            request_id=self.packet['request_id'], packet_digest=self.packet['packet_digest'], items=[],
            assessment=dict(proposed_answerability='unresolved', rationale='Local source validation.',
                            support_refs=[self.packet['content']['supports'][0]['alias']]))), **self.options)
        if self.body != wire.body(self.messages, self.config['model']):
            raise ValueError('D2_REQUEST_CHANGED')

    def preview(self):
        self.check()
        return dict(contract='d2-authorized-preview-v1', provider=self.config['provider'], model=self.config['model'],
                    issue=self.packet['content']['issue'], source=self.packet['content']['source'],
                    view=self.packet['content']['view'], packet_digest=self.packet['packet_digest'],
                    body_sha256=hashlib.sha256(self.body).hexdigest(), body_bytes=len(self.body),
                    fits=len(self.body)<=wire.LIMIT, limits=deepcopy(LIMITS),
                    canonical_packet=deepcopy(self.packet['content']), messages=deepcopy(self.messages),
                    original_s3=deepcopy(self.history._original), provider_requests=0, durable=False)


def prepare(root, run_id, issue_id, config, *, exploratory=False):
    from forensic_assistant.ai.settings import validate
    config = validate(config)
    history = d2.open_history(root, run_id)
    options = dict(exploratory=exploratory, issue_ids=[issue_id])
    preview = history.preview(**options)
    if len(preview['packets']) != 1:
        raise ValueError('D2_NO_COMPLETE_PACKET')
    return Prepared(history, preview['packets'][0], config, options)


class _Permit:
    def __init__(self, prepared):
        self.prepared = prepared
        self.seal = prepared.identity()
        self.approved = time.monotonic()
        self.used = False
        self.lock = threading.Lock()
        self.grant = dict(contract=GRANT, provider=prepared.config['provider'], model=prepared.config['model'],
                          source=deepcopy(prepared.packet['content']['source']), view=deepcopy(prepared.packet['content']['view']),
                          issue=prepared.packet['content']['issue']['id'], packet_digest=prepared.packet['packet_digest'],
                          request_sha256=hashlib.sha256(prepared.body).hexdigest(), limits=deepcopy(LIMITS))
        self.grant_seal = digest(self.grant)


def authorize(prepared, confirmation):
    """UI supplies an explicit approval callback; configuration alone is insufficient."""
    preview = prepared.preview()
    if not preview['fits']:
        raise ValueError('D2_BODY_TOO_LARGE')
    if not callable(confirmation) or confirmation(deepcopy(preview)) is not True:
        raise ValueError('D2_NOT_AUTHORIZED')
    if prepared.identity() != prepared._seal:
        raise ValueError('D2_PREPARED_CHANGED')
    return _Permit(prepared)


def _child(connection, gate, request):
    deadline = request['deadline']
    if not gate.wait(max(0, deadline-time.monotonic())) or time.monotonic()>=deadline:
        return
    if os.name != 'nt':
        os.setsid()
    attempted = False
    try:
        from forensic_assistant.ai.settings import load
        current = load()
        if (current['provider'],current['model']) != ('openai',request['config']['model']):
            raise ValueError('D2_PROVIDER_CHANGED')
        prepared = prepare(request['root'], request['run_id'], request['issue'], request['config'],
                           exploratory=request['exploratory'])
        if prepared.identity()!=request['seal']:
            raise ValueError('D2_SOURCE_CHANGED')
        from forensic_assistant.ai.backend import ModelBackend
        remaining = deadline-time.monotonic()
        if remaining<=0:
            raise TimeoutError()
        client = ModelBackend(config=request['config'], timeout=min(55,remaining))
        if (client.provider_name,client.model_name)!=('openai',prepared.config['model']):
            raise ValueError('D2_PROVIDER_CHANGED')
        attempted = True
        connection.send_bytes(b'{"phase":"attempt"}')
        response = client.complete_d2(prepared.messages, hashlib.sha256(prepared.body).hexdigest())
        if time.monotonic()>=deadline:
            raise TimeoutError()
        validated = prepared.history.validate(prepared.packet, wire.expand_response(response['text'],prepared.packet), **prepared.options)
        connection.send_bytes(json.dumps(dict(status='accepted', validated=validated,usage=response.get('usage',{}),attempted=True)).encode())
    except BaseException as exc:
        from forensic_assistant.ai.provider_diagnostics import ProviderFailure
        reason = exc.category if isinstance(exc,ProviderFailure) else 'timeout' if isinstance(exc,TimeoutError) else 'validation_or_worker_failure'
        connection.send_bytes(json.dumps(dict(status='rejected',reason=reason,attempted=attempted)).encode())
    finally:
        connection.close()


def execute(permit, *, cancelled=None):
    """One process-isolated attempt, including startup; five seconds reserved for cleanup."""
    if type(permit) is not _Permit:
        raise ValueError('D2_NOT_AUTHORIZED')
    with permit.lock:
        if permit.used or permit.seal!=permit.prepared.identity() or permit.grant_seal!=digest(permit.grant):
            raise ValueError('D2_GRANT_INVALID_OR_CONSUMED')
        if time.monotonic()>=permit.approved+55:
            raise ValueError('D2_GRANT_EXPIRED')
        permit.used = True
    p = permit.prepared
    if len(p.body)>wire.LIMIT:
        raise ValueError('D2_BODY_TOO_LARGE')
    deadline, end = permit.approved+55, permit.approved+60
    if cancelled is not None and cancelled.is_set():
        return dict(status='interrupted',reason='cancelled',durable=False,grant=deepcopy(permit.grant),
                    attempts=0,attempt_allocation_consumed=True,network_outcome='not_dispatched',
                    elapsed_seconds=round(time.monotonic()-permit.approved,3),cleanup='confirmed',lookups=0)
    request=dict(root=str(p.history._root),run_id=p.history._anchor['run_id'],issue=p.packet['content']['issue']['id'],
                 config=p.config, exploratory=p.options['exploratory'],seal=permit.seal,deadline=deadline)
    context=multiprocessing.get_context('spawn')
    parent,child=context.Pipe(duplex=False);gate=context.Event()
    process=context.Process(target=_child,args=(child,gate,request),daemon=False)
    launch=Launch(process);job=None;inbox=queue.Queue();attempted=False;released=False
    result=dict(status='interrupted',reason='worker_failure')
    def receive():
        try:
            while True:inbox.put(json.loads(parent.recv_bytes(131072)))
        except (EOFError,OSError,ValueError):inbox.put(None)
    try:
        launch.thread.start();launch.wait(deadline)
        child.close()
        job=WorkerJob(process.pid) if os.name=='nt' else None
        if cancelled is not None and cancelled.is_set():
            raise KeyboardInterrupt()
        gate.set();released=True;threading.Thread(target=receive,daemon=True).start()
        while time.monotonic()<deadline:
            if cancelled is not None and cancelled.is_set():
                result=dict(status='interrupted',reason='cancelled');break
            try:message=inbox.get(timeout=min(.05,max(.001,deadline-time.monotonic())))
            except queue.Empty:continue
            if message is None:break
            if message.get('phase')=='attempt':attempted=True;continue
            result=message;break
        else:result=dict(status='interrupted',reason='timeout')
    except KeyboardInterrupt:
        result=dict(status='interrupted',reason='cancelled')
    except TimeoutError:
        result=dict(status='interrupted',reason='timeout')
    except Exception:
        result=dict(status='rejected',reason='worker_startup_failure')
    finally:
        if not launch.done.wait(max(0,end-time.monotonic())):
            raise CleanupError('D2 CLEANUP_LIMITATION: process startup unresolved')
        if process.pid is not None and not _stop(process,job,end):
            raise CleanupError('D2 CLEANUP_LIMITATION: worker termination unconfirmed')
        parent.close();child.close()
    # Cancellation may race the phase message. Absence of IPC is not proof of no send.
    confirmed = result.pop('attempted', None)
    attempts = int(confirmed) if type(confirmed) is bool else 1 if attempted else None if released else 0
    return dict(**result,durable=False,grant=deepcopy(permit.grant),attempts=attempts,
                attempt_allocation_consumed=True,network_outcome='not_dispatched' if attempts==0 else 'may_have_been_exposed',
                elapsed_seconds=round(time.monotonic()-permit.approved,3),cleanup='confirmed',lookups=0)
