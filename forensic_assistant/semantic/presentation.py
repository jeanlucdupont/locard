"""Human-only semantic presentation; machine manifests remain unmodified."""
import sys
import time

from forensic_assistant.retrieval.presentation import safe_text as safe

NOTES = ('Semantic similarity is derived retrieval metadata, not forensic evidence.',
         'Semantic retrieval locates evidence; it does not create evidence.',
         'Similarity score is not confidence of maliciousness.')

# Human display heuristic only, studied with the pinned BGE/representation 2.
# Not a relevance classifier; never used by JSON, ASK, or evidence selection.
BGE_DISPLAY_CUTOFF = 0.5


def display_hits(result, show_weak=False):
    from .model import MODELS
    identity = result.get('model', {})
    applies = ((identity.get('model_id'), identity.get('revision')) == MODELS['bge']
               and result.get('representation_version') == '2')
    hits = result['results']
    if show_weak or not applies:
        return hits, None
    return [hit for hit in hits if hit['semantic_similarity'] >= BGE_DISPLAY_CUTOFF], BGE_DISPLAY_CUTOFF


class Progress:
    def __init__(self, args, *, stream=None, clock=time.monotonic):
        self.stream = stream if stream is not None else sys.stderr
        self.enabled = (not args.json and self.stream.isatty()
                        and not getattr(args, 'output_file', None) and not getattr(args, 'append_file', None))
        self.clock = clock
        self.last = None

    def __call__(self, state):
        if not self.enabled:
            return
        now = self.clock()
        if self.last is not None and now - self.last < 1:
            return
        self.last = now
        print(f"Embedding: {state['records']} / {state['total']} records | Vectors: {state['vectors']}"
              f" | Elapsed: {state['elapsed']:.1f}s | Model: {safe(state['model'])} | Device: {state['device']}",
              file=self.stream, flush=True)


def render(result, args, palette):
    lines = []
    def line(label, value):
        lines.append(palette('key', label + ': ') + safe(value))
    command = args.semantic_command
    if command == 'status':
        lines.append(palette('heading', 'Semantic search'))
        line('Status', result['state'].replace('_', ' ').capitalize())
        line('Runtime dependencies', result['runtime']['state'])
        line('Embedding model', result['model_state'])
        line('Case index', result['index_state'])
        if result.get('model_location'):
            line('Model location', result['model_location'])
        if result.get('model'):
            line('Model', result['model']['model_id'])
        if result.get('index', {}).get('indexed') is not None:
            index = result['index']
            line('Indexed evidence', f"{index['indexed']} / {result['current_evidence_records']}")
            line('Vectors', index['vectors'])
            line('Built', index.get('built_utc', 'unknown'))
            line('Backend', index['model'].get('backend', 'unknown'))
            line('Device', 'CPU')
        elif 'current_evidence_records' in result:
            line('Evidence records', result['current_evidence_records'])
        if result['state'] == 'dependencies_missing':
            line('Python', result['runtime']['python'])
            for failure in result['runtime']['failures']:
                line('Dependency', failure)
        reason = result.get('reason') or result.get('index', {}).get('reason')
        if reason:
            line('Reason', reason)
        line('Next step', result['next_step'])
    elif command == 'setup':
        lines.append(palette('heading', 'Semantic model installed.'))
        line('Model', result['model_id'])
        line('Location', result['location'])
        line('Files', len(result['files']))
        line('Verification', 'Passed')
        line('Next step', 'semantic build')
    elif command in ('build', 'rebuild'):
        lines.append(palette('heading', 'Semantic index built.'))
        line('Model', result['model']['model_id'])
        line('Device', 'CPU')
        line('Evidence indexed', f"{result['indexed']} / {result['eligible']}")
        line('Vectors', result['vectors'])
        line('Skipped', result['skipped'])
        line('Over-limit representations', result['over_limit_records'])
        line('Chunked records', result['chunked_records'])
        line('Truncated records', result['truncated_records'])
        line('Build time', f"{result['build_seconds']:.1f}s")
        line('Index state', 'Ready')
    else:
        line('Semantic search', args.question)
        hits, cutoff = display_hits(result, getattr(args, 'show_weak', False))
        lines.append('Nearest-neighbor candidates; usefulness is not established by similarity.')
        if cutoff is not None and len(hits) < len(result['results']):
            if not hits:
                lines.append('No semantic candidates meet the display cutoff.')
            line('Display cutoff', f'{cutoff:.3f} (not proof of irrelevance)')
            line('Best similarity', f"{max(h['semantic_similarity'] for h in result['results']):.3f}")
            lines.append('Use --show-weak to display omitted candidates; JSON retains all results.')
        for position, hit in enumerate(hits, 1):
            excerpt = hit['excerpt'].splitlines()
            keys = ('reconstructed_path:', 'original:', 'process_name:', 'executable:', 'key_path:', 'filename:')
            subject = next((row.partition(': ')[2] for key in keys for row in excerpt if row.startswith(key)), hit['artifact_type'])
            lines += ['', f"{position}. {hit['semantic_similarity']:.3f}  {safe(subject)}"]
            line('   Artifact', hit['source_type'].upper())
            lines.append('   ' + palette('evidence_id', 'ID: ' + safe(hit['evidence_id'])))
            useful = [row for row in excerpt if row and not row.endswith(':')
                      and not row.startswith(('Artifact:', 'semantics:', 'source_type:', 'artifact_type:'))]
            for row in useful[:3]:
                lines.append('   ' + safe(row[:240]))
        lines += ['', f"Showing {len(hits)} semantic results"]
        line('Candidate vectors', result['candidate_vectors'])
    lines += ['', palette('forensic_note', 'Forensic notes'), *(palette('forensic_note', '- ' + note) for note in NOTES)]
    return '\n'.join(lines)
