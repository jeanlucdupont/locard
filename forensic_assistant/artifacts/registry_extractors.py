"""Small local extractor registry. Every view links the actual key and value."""
from dataclasses import dataclass
import json
import re
from forensic_assistant.database.artifacts import dump,add_object
from forensic_assistant.artifacts.paths import executable_reference


@dataclass(frozen=True)
class Extractor:
    name:str
    category:str
    key_pattern:str
    value_pattern:str='.*'
    path_role:str|None=None
    version:str='1'

    def matches(self,key,name):return bool(re.search(self.key_pattern,key,re.I) and re.fullmatch(self.value_pattern,name,re.I))


EXTRACTORS=(
    Extractor('run','persistence',r'(^|\\)(Run|RunOnce)$',path_role='persistence_target'),
    Extractor('services','persistence',r'^ControlSet\d{3}\\Services\\[^\\]+(\\Parameters)?$',r'ImagePath|ServiceDll','persistence_target'),
    Extractor('winlogon','persistence',r'Microsoft\\Windows NT\\CurrentVersion\\Winlogon$',r'Shell|Userinit|Taskman','persistence_target'),
    Extractor('shell','startup_configuration',r'Explorer\\(User Shell Folders|Shell Folders)$',r'.*Startup.*','startup_directory'),
    Extractor('profiles','profile',r'Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\[^\\]+$',r'ProfileImagePath','profile_directory'),
    Extractor('usb','device_history',r'^ControlSet\d{3}\\Enum\\(USB|USBSTOR)\\'),
    Extractor('rdp','rdp_configuration_history',r'(Terminal Server|Terminal Server Client)(\\|$)'),
    Extractor('recent','recent_text',r'(RunMRU|TypedPaths|TypedURLs)$'),
)


def extract_all(db):
    cursor=db.execute('SELECT v.*,k.key_path FROM registry_values v JOIN registry_keys k ON k.evidence_id=v.key_id ORDER BY v.evidence_id')
    while rows:=cursor.fetchmany(500):
        for r in rows:
            decoded=json.loads(r['decoded_json'])
            for ex in EXTRACTORS:
                if not ex.matches(r['key_path'],r['value_name']):continue
                details=dict(key_id=r['key_id'],key_path=r['key_path'],value_name=r['value_name'],
                             observation='Snapshot value; containing key last-write does not date value creation')
                db.execute('INSERT INTO registry_views VALUES (?,?,?,?,?) ON CONFLICT DO NOTHING',
                           (r['evidence_id'],ex.name,ex.version,ex.category,dump(details)))
                if ex.path_role and isinstance(decoded,str):
                    path=executable_reference(decoded) if ex.path_role=='persistence_target' else decoded
                    if path:add_object(db,r['evidence_id'],ex.name,ex.path_role,path)
