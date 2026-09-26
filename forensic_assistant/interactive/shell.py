"""Synchronous interface over the ordinary Locard parser and dispatcher."""
import gc
import sqlite3
from forensic_assistant.interactive.case import validate
from forensic_assistant.interactive.console import Reader, safe
from forensic_assistant.interactive.state import State, state_path


def split(line):
    """Backslashes are literal. Single/double quotes group; doubled quotes escape."""
    if len(line)>65536 or any(c in line for c in '\r\n\x00'):
        raise ValueError('Invalid or oversized input line')
    words=[];word=[];quote=None;started=False;i=0
    while i<len(line):
        c=line[i]
        if quote:
            if c==quote:
                if i+1<len(line) and line[i+1]==quote:word.append(c);i+=1
                else:quote=None
            else:word.append(c)
        elif c in ('"',"'"):
            quote=c;started=True
        elif c.isspace():
            if started:words.append(''.join(word));word=[];started=False
        elif c in ';|&<>':raise ValueError('Shell operators are not supported; quote literal values')
        else:word.append(c);started=True
        i+=1
    if quote:raise ValueError('Unclosed quote')
    if started:words.append(''.join(word))
    return words


class Shell:
    def __init__(self, state, reader=None):
        self.state=state;self.reader=reader or Reader();self.active=None;self.last_status=0

    def activate(self,path):
        target=validate(path)
        self.active=target
        self.reader.clear()
        try:self.state.remember(target)
        except (OSError,ValueError) as exc:print('Recent case not saved: '+safe(exc))
        print('Database: '+safe(target)+'\nSchema: 3 (structure checked; evidence conclusions not validated)')

    def choose(self,path=None):
        if path is not None:
            self.activate(path);return True
        if self.active:print('Current database: '+safe(self.active))
        if self.state.recent:
            print('Recent databases:')
            for n,value in enumerate(self.state.recent,1):print(f'  {n}. '+safe(value))
        while True:
            try:
                line=self.reader.read('Database path or recent number (Enter cancels): ').strip()
                if not line or line in ('exit','quit'):return False
                if line.isdecimal() and 1<=int(line)<=len(self.state.recent):path=self.state.recent[int(line)-1]
                elif line.startswith(('"',"'")):
                    parts=split(line)
                    if len(parts)!=1:raise ValueError('Enter one database path')
                    path=parts[0]
                else:path=line
                self.activate(path);return True
            except (OSError,ValueError,sqlite3.Error) as exc:print('Cannot select database: '+safe(exc))
            except (EOFError,KeyboardInterrupt):print();return False

    def startup(self):
        from forensic_assistant import __version__
        print('Locard '+__version__+'\n')
        if self.state.warning:print(safe(self.state.warning))
        if self.state.recent:
            try:validate(self.state.recent[0])
            except (OSError,ValueError,sqlite3.Error) as exc:
                print('Remembered database unavailable: '+safe(exc))
                return self.choose()
            except (EOFError,KeyboardInterrupt):print();return False
            print('Last database:\n'+safe(self.state.recent[0])+'\n')
            try:
                response=self.reader.read('Use this database? [Y/n]: ').strip().casefold()
                if response in ('','y','yes'):
                    try:self.activate(self.state.recent[0]);return True
                    except (OSError,ValueError,sqlite3.Error) as exc:print('Remembered database unavailable: '+safe(exc))
                elif response in ('exit','quit'):return False
            except (EOFError,KeyboardInterrupt):print();return False
        return self.choose()

    def run(self):
        from forensic_assistant.cli import build_parser,dispatch
        if not self.startup():return 0
        try:
            while True:
                try:validate(self.active)
                except KeyboardInterrupt:
                    print('\nValidation interrupted; retrying before accepting commands.');continue
                except (OSError,ValueError,sqlite3.Error) as exc:
                    print('Active case unavailable: '+safe(exc));self.active=None;self.reader.clear()
                    if not self.choose():return 0
                label=safe(self.active.parent.name+'/'+self.active.name)
                if len(label)>80:label=label[:38]+'...'+label[-39:]
                executing=False
                try:
                    words=split(self.reader.read('locard['+label+']> ',remember=True))
                    if not words:continue
                    if words[0] in ('exit','quit'):
                        if len(words)!=1:raise ValueError('exit takes no arguments')
                        return 0
                    if words[0]=='case':
                        if len(words)>2:raise ValueError('Use case or case "database path"')
                        self.choose(words[1] if len(words)==2 else None);continue
                    if words[0]=='help':
                        if len(words)==1:print('Shell: help [command], case [path], exit, quit. No shell execution or persistent history.')
                        words=words[1:]+['--help']
                    parser=build_parser()
                    try:args=parser.parse_args(['--db',str(self.active),*words])
                    except SystemExit as exc:self.last_status=int(exc.code);continue
                    # Also rejects argparse global-option abbreviations/equals forms.
                    if args.db!=str(self.active) or any(w=='--db' or w.startswith('--db=') for w in words):
                        raise ValueError('Use case to change the active database')
                    executing=True
                    self.last_status=dispatch(args,existing_only=True)
                except EOFError:print();return 0
                except KeyboardInterrupt:
                    print('\nInterrupted. Completed ingestion files remain committed; inspect status for run outcomes.'
                          if executing else '\nInput cancelled.')
                    self.last_status=130
                except (ValueError,OSError,sqlite3.Error) as exc:
                    print('Locard: '+safe(exc));self.last_status=2
                finally:
                    # Release cyclic command-local objects; retain only schema metadata.
                    gc.collect()
        finally:self.reader.clear()


def run():
    try:state=State(state_path()).load()
    except (OSError,ValueError) as exc:
        state=State(None);state.warning=str(exc)
    return Shell(state).run()
