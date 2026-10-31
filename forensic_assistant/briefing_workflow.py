"""Explicit analyst entry workflows; editor launch never uses a shell."""
import json
import os
from pathlib import Path
import subprocess
import uuid
from forensic_assistant.interactive.console import safe
from forensic_assistant.briefing_store import FIELDS, content
from forensic_assistant.investigation_ai.storage import local_path, DirectoryGuard
from forensic_assistant.investigation_ai.snapshot import _private_mkdir


def read_answer(read, prompt):
    value = read(prompt)
    if value.strip().casefold() == 'cancel':raise KeyboardInterrupt()
    return value


def view(state):
    if not state:return {'kind':'saved_briefing','message':'No saved briefing. Use briefing --interview or briefing --edit.'}
    revision = state['revisions'][-1]
    last = state['analyses'][-1] if state['analyses'] else None
    return {'kind':'saved_briefing','revision':revision,'last_analysis':last,
            'analysis_stale':bool(last and last['digest'] != revision['digest']),
            'analysis_storage':'Analysis metadata only; AI responses and evidence packets are not stored. --analyze generates a new analysis.'}


def render(value):
    if value.get('message'):return value['message']
    revision=value['revision']; lines=['Incident briefing — analyst assertions, not evidence','']
    for key,label in FIELDS.items():
        text=revision['content']['answers'][key]
        if text:
            lines.extend([label,*('  '+safe(line) for line in text.splitlines())])
    narrative=revision['content']['narrative']
    if narrative:lines.extend(['Narrative',*('  '+safe(line) for line in narrative.splitlines())])
    for session in revision['content'].get('interviews', []):
        lines.append('Interview ('+safe(session['purpose'])+') — original analyst responses')
        for number, turn in enumerate(session['turns'], 1):
            lines.append('  '+str(number)+'. '+safe(turn['question_origin'])+' question: '+safe(turn['question']))
            lines.append('     Analyst: '+safe(turn['answer']) if turn['answer_status']=='answered' else '     Skipped — unknown, not a negative assertion')
            if turn['supersedes'] is not None:lines.append('     Correction to response '+str(turn['supersedes']))
    lines.extend(['', 'Briefing revision: '+str(revision['revision']), 'Modified: '+safe(revision['modified'])])
    last=value['last_analysis']
    lines.append('Last analysis: '+('revision '+str(last['revision'])+(' — outdated; reanalysis recommended' if value['analysis_stale'] else ' — current revision') if last else 'not recorded'))
    lines.append(value['analysis_storage'])
    return '\n'.join(lines)


def wizard(current, read):
    value=content(current['answers'],current['narrative'],current.get('interviews'))
    print('All answers optional. Enter retains an answer; /clear clears it; cancel exits. Multiple values may be separated with semicolons.')
    for key,label in FIELDS.items():
        if value['answers'][key]:print(label+': '+safe(value['answers'][key]))
        answer=read_answer(read,label+': ')
        if answer == '/clear':value['answers'][key]=''
        elif answer:value['answers'][key]=answer
    content(value['answers'],value['narrative'],value.get('interviews'))
    print('Proposed briefing (unknown answers remain unspecified):')
    for key,label in FIELDS.items():
        if value['answers'][key]:print('  '+label+': '+safe(value['answers'][key]))
    print('  Existing narrative retained.' if value['narrative'] else '  No free-text narrative.')
    return value if read_answer(read,'Save briefing revision? [y/N]: ').casefold() in ('y','yes') else None


def editor_args(path):
    configured=os.environ.get('LOCARD_BRIEFING_EDITOR')
    if configured:
        try:args=json.loads(configured)
        except ValueError:raise ValueError('LOCARD_BRIEFING_EDITOR must be a JSON argument array.') from None
        if type(args) is not list or not args or any(type(a) is not str or '\0' in a for a in args):
            raise ValueError('Invalid editor argument array.')
        if not Path(args[0]).is_absolute() or Path(args[0]).suffix.lower() != '.exe' or not Path(args[0]).is_file():
            raise ValueError('Configured editor must be an absolute existing executable (.exe).')
        if args.count('{file}') != 1 or any('{file}' in a and a != '{file}' for a in args):
            raise ValueError('Editor arguments require exactly one standalone {file} placeholder.')
        return [str(path) if a=='{file}' else a for a in args]
    if os.name != 'nt':raise ValueError('Configure LOCARD_BRIEFING_EDITOR for this platform.')
    return [str(Path(os.environ['SystemRoot'])/'System32'/'notepad.exe'),str(path)]


def edit(store, current, read):
    # Private per-edit directory in the case workspace, not the system temp folder.
    folder=local_path(store.case.parent/('.briefing-edit-'+uuid.uuid4().hex))
    with DirectoryGuard(store.case.parent):
        _private_mkdir(folder)
        path=folder/'narrative.txt'
        try:
            with DirectoryGuard(folder):
                path.write_bytes(current['narrative'].encode('utf-8'))
                args=editor_args(path)
                process=subprocess.Popen(args, shell=False)
                try:
                    code=process.wait()
                except BaseException:
                    if process.poll() is None:
                        process.terminate()
                        try:process.wait(timeout=5)
                        except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
                    raise
                if code:raise ValueError('Editor failed; briefing unchanged.')
                # Modern Notepad/GUI editors may delegate to another process.
                # Process exit alone is never interpreted as completed editing.
                if read_answer(read,'Save and CLOSE the document in the editor, then import it? [y/N]: ').casefold() not in ('y','yes'):
                    return None
                local_path(path)
                if not path.is_file() or path.stat().st_nlink != 1:raise ValueError('Editor output is not a private regular file.')
                with path.open('rb') as stream:raw=stream.read(32769)
                if len(raw)>32768:raise ValueError('Editor content exceeds 32 KiB; briefing unchanged.')
                try:text=raw.decode('utf-8')
                except UnicodeError:raise ValueError('Editor must save UTF-8; briefing unchanged.') from None
                return content(current['answers'],text,current.get('interviews'))
        finally:
            # Do not recursively delete editor-created files or follow redirects.
            try:
                local_path(path)
                if path.exists():path.unlink()
                folder.rmdir()
            except (OSError, ValueError):
                print('Editor temporary-data cleanup incomplete; review '+safe(folder))
