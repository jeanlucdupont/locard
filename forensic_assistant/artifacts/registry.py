"""Offline hive traversal. Last-write is a key property, never value creation."""
import base64
from forensic_assistant.artifacts.storage import base_record
from forensic_assistant.artifacts.times import filetime


def identify_hive(f):
    candidates=[]
    signatures={'SYSTEM':('Select','ControlSet001'), 'SOFTWARE':('Microsoft\\Windows NT\\CurrentVersion',),
                'SAM':('SAM\\Domains',),'SECURITY':('Policy',),'NTUSER':('Software\\Microsoft\\Windows\\CurrentVersion\\Explorer',),
                'USRCLASS':('Local Settings\\Software\\Microsoft\\Windows\\Shell',)}
    for kind,paths in signatures.items():
        if all(f.get_key_by_path(p) is not None for p in paths):candidates.append(kind)
    return (candidates[0],'structural key signature') if len(candidates)==1 else ('UNKNOWN','ambiguous or absent structural signatures: '+','.join(candidates))


def decode_value(v,raw):
    # Never expand REG_EXPAND_SZ, decrypt SAM/SECURITY, or execute text.
    if v.type in (1,2,6):return raw.decode('utf-16le').rstrip('\x00')
    if v.type==7:return raw.decode('utf-16le').rstrip('\x00').split('\x00')
    if v.type in (4,5) and len(raw)==4:return int.from_bytes(raw,'big' if v.type==5 else 'little')
    if v.type==11 and len(raw)==8:return int.from_bytes(raw,'little')
    return {'encoding':'base64','data':base64.b64encode(raw).decode()}


def parse(path,sha):
    import pyregf
    with open(path,'rb') as stream:
        head=stream.read(512);stream.seek(0)
        if head[:4]!=b'regf':raise ValueError('Invalid REGF header')
        f=pyregf.open_file_object(stream)
        try:
            kind,basis=identify_hive(f)
            dirty=head[4:8]!=head[8:12]
            warnings=[]
            if dirty:warnings.append('Dirty hive: transaction logs were not replayed; snapshot may be inconsistent')
            if f.corrupted:warnings.append('Parser reports hive corruption')
            if kind=='UNKNOWN':warnings.append('Hive identity unknown; no filename-based assumption')
            hive=dict(type=kind,basis=basis,dirty=dirty,warnings=warnings)
            stack=[(f.root_key,'',None,0)];seen=set()
            while stack:
                k,path_text,parent,depth=stack.pop()
                try:
                    offset=k.offset
                    if offset in seen:raise ValueError('Repeated Registry key cell/cycle')
                    seen.add(offset)
                    if depth>256:raise ValueError('Registry depth limit reached')
                    eid=f'REGISTRY:{sha}:KeyOffset:{offset}'
                    local=warnings+(['Parser reports key corruption'] if k.corrupted else [])
                    yield dict(record=base_record(eid,'registry','registry_key',{'offset':offset,'cell_type':'nk'},local),
                               detail=dict(key_path=path_text,parent_id=parent,offset=offset,hive=hive),
                               timestamps=[filetime(k.get_last_written_time_as_integer(),'LastWrite','Registry Key LastWrite',
                                                    'Key last-write timestamp; not individual value creation')])
                    if k.number_of_values>100000 or k.number_of_sub_keys>100000:raise ValueError('Registry collection limit reached')
                    for i in range(k.number_of_values):
                        v=None
                        try:
                            v=k.get_value(i);vo=v.offset;vid=f'REGISTRY:{sha}:ValueOffset:{vo}'
                            if v.data_size>16*1024*1024:raise ValueError('Registry value exceeds 16 MiB; raw bytes remain in source')
                            raw=v.data or b'';value_warnings=local+(['Parser reports value corruption'] if v.corrupted else [])
                            try:decoded=decode_value(v,raw)
                            except (UnicodeError,ValueError) as exc:
                                decoded={'encoding':'base64','data':base64.b64encode(raw).decode()};value_warnings.append(f'Value decoding failed: {exc}')
                            yield dict(record=base_record(vid,'registry','registry_value',{'offset':vo,'cell_type':'vk'},value_warnings),
                                       detail=dict(hive=hive,key_id=eid,offset=vo,value_name=v.name or '',value_type=v.type,
                                                   raw_data=base64.b64encode(raw).decode(),decoded=decoded))
                        except Exception as exc:yield {'error':f'Value {i}: {type(exc).__name__}: {exc}','locator':{'offset':v.offset if v else offset}}
                    children=[]
                    for i in range(k.number_of_sub_keys):
                        try:
                            child=k.get_sub_key(i);children.append((child,path_text+'\\'+child.name if path_text else child.name,eid,depth+1))
                        except Exception as exc:yield {'error':f'Subkey {i}: {exc}','locator':{'offset':offset}}
                    stack.extend(reversed(children))
                except Exception as exc:yield {'error':f'Key traversal: {type(exc).__name__}: {exc}','locator':{'offset':getattr(k,'offset',None)}}
        finally:f.close()
