"""Conservative lexical command features. Never a shell parser or verdict engine."""
import base64
import binascii
import ntpath
import re
from forensic_assistant.artifacts.paths import executable_reference

VERSION='execution-features-v1'
# Per-field technical bound, not a candidate-population limit.
MAX_TEXT=32768
INTERPRETERS=frozenset(('cmd.exe','cmd','powershell.exe','powershell','pwsh.exe','pwsh','wscript.exe','cscript.exe','mshta.exe','python.exe','python','bash.exe','bash','sh'))
APPLICATIONS=frozenset(('winword.exe','excel.exe','powerpnt.exe','outlook.exe','chrome.exe','msedge.exe','firefox.exe'))
DEFINITIONS={
 'shell':'Recorded image or first lexical executable is a recognized interpreter',
 'nested_interpreter':'More than one interpreter-like token; quoting does not establish execution',
 'chaining':'Shell-like &&, ||, semicolon or pipeline punctuation',
 'quoting_ambiguity':'Unbalanced quotes or escaped quotes; no equivalent command is reconstructed',
 'escaping':'Caret or backtick escape syntax is present',
 'environment_reference':'Unexpanded percent-variable or PowerShell environment reference',
 'encoded_argument':'Recognized PowerShell encoded-command option',
 'indirect_construction':'Expression evaluation, Base64 conversion or command substitution syntax',
 'concatenation':'Quoted string concatenation syntax',
 'interpreter_flags':'NoProfile, hidden window or execution-policy option',
 'remote_reference':'URL or UNC-like lexical reference; no network contact',
 'local_path':'Drive-qualified or unexpanded Windows path',
 'output_redirection':'Output redirection punctuation or output-file option',
 'registry_operation':'reg add/delete/import or Registry item/property command syntax',
 'service_task_operation':'sc/schtasks or service/task PowerShell command syntax',
 'user_writable_reference':'Recorded path references Users, AppData, Temp or Downloads; actual ACLs unknown',
 'long_command':'More than 2048 characters; length alone has no maliciousness meaning',
 'interactive_parent_interpreter':'Recorded browser/document parent and interpreter child; no inferred process instance',
}


def features(command,image=None,parent=None):
    notes=[];found=set();decoded=None
    if not isinstance(command,str):command=''
    original_length=len(command.encode('utf-8'));limited=original_length>MAX_TEXT
    text=command.encode('utf-8')[:MAX_TEXT].decode('utf-8','ignore')
    if limited:notes.append('Command analysis byte bound reached; features concern a prefix, not complete command semantics')
    executable=image or executable_reference(text);base=ntpath.basename(executable or '').casefold()
    tokens=re.findall(r'"[^"\r\n]*"|\x27[^\x27\r\n]*\x27|[^\s]+',text)
    interpreter_tokens=[t for t in tokens if ntpath.basename(t.strip('"\x27;|&()')).casefold() in INTERPRETERS]
    if base in INTERPRETERS:found.add('shell')
    if len(interpreter_tokens)>1:found.add('nested_interpreter')
    patterns={
      'chaining':r'&&|\|\||[;|]', 'escaping':r'[\^`]',
      'environment_reference':r'%[^%\s]+%|\$env:[\w]+',
      'indirect_construction':r'\$\(|\b(?:Invoke-Expression|IEX|FromBase64String)\b',
      'concatenation':r'["\x27]\s*\+\s*["\x27]',
      'interpreter_flags':r'(?i)(?<!\w)-(?:nop|noprofile|executionpolicy|ep|windowstyle|w)\b',
      'remote_reference':r'(?i)\b[a-z][a-z0-9+.-]*://|\\\\[^\s\\]+\\',
      'local_path':r'(?i)\b[a-z]:\\|%[^%]+%\\',
      'output_redirection':r'>>?|(?i:-(?:out(?:file)?|output))\b',
      'registry_operation':r'(?i)\breg(?:\.exe)?\s+(?:add|delete|import)\b|\b(?:Set|New|Remove)-ItemProperty\b',
      'service_task_operation':r'(?i)\b(?:sc(?:\.exe)?\s+(?:create|config|start|delete)|schtasks(?:\.exe)?\s+/|(?:New|Set|Start)-Service|Register-ScheduledTask)\b',
      'user_writable_reference':r'(?i)\\(?:Users|AppData|Temp|Downloads)\\|%(?:TEMP|TMP|APPDATA|USERPROFILE)%',
    }
    for name,pattern in patterns.items():
        if re.search(pattern,text):found.add(name)
    if text.count('"')%2 or text.count("'")%2 or '\\"' in text:found.add('quoting_ambiguity');notes.append('Lexical parsing is ambiguous; original command remains authoritative')
    if len(command)>2048:found.add('long_command')
    if ntpath.basename(parent or '').casefold() in APPLICATIONS and base in INTERPRETERS:found.add('interactive_parent_interpreter')
    match=re.search(r'(?i)(?<![\w-])-(?:enc|encodedcommand)\s+([^\s]+)',text)
    if match and base in ('powershell.exe','powershell','pwsh.exe','pwsh'):
        found.add('encoded_argument');token=match[1].strip('"\x27')
        decoded=dict(method='Base64 to UTF-16LE, one level only',status='unsupported_or_invalid',text=None,derived=True)
        try:
            raw=base64.b64decode(token,validate=True)
            value=raw.decode('utf-16-le')
            if len(raw)>MAX_TEXT or any(ord(c)<32 and c not in '\t\r\n' for c in value):raise ValueError('Not supported script text')
            decoded.update(status='decoded',text=value)
        except (ValueError,UnicodeError,binascii.Error):pass
    # Preserve every literal token. Never erase paths, domains or operation arguments.
    return dict(version=VERSION,features=sorted(found),executable=executable,basename=base,
                argument_pattern=tokens,decoded=decoded,limitations=notes,analysis_truncated=limited,
                lexical_only=True,command_bytes=original_length)
