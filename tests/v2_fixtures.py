"""Small synthetic binary fixtures, never copied examiner evidence."""
import struct

FT=132042381048777787


def mft_record(number=6,sequence=1,parent=5,parent_sequence=1,names=('payload.exe',),allocated=True,directory=False):
    raw=bytearray(1024)
    struct.pack_into('<4sHHQHHHHIIQH',raw,0,b'FILE',48,3,0,sequence,len(names),56,(1 if allocated else 0)|(2 if directory else 0),0,1024,0,4)
    pos=56
    def attribute(kind,value,instance):
        nonlocal pos
        length=(24+len(value)+7)//8*8
        struct.pack_into('<IIBBHHHIHBB',raw,pos,kind,length,0,0,0,0,instance,len(value),24,0,0)
        raw[pos+24:pos+24+len(value)]=value;pos+=length
    attribute(16,struct.pack('<QQQQIIIIIIQQ',FT,FT+10,FT+20,FT+30,32,0,0,0,0,0,0,0),0)
    for i,name in enumerate(names):
        encoded=name.encode('utf-16le')
        value=struct.pack('<QQQQQQQIIBB',parent|(parent_sequence<<48),FT+100,FT+110,FT+120,FT+130,4096,50,32,0,len(encoded)//2,1)+encoded
        attribute(48,value,i+1)
    struct.pack_into('<I',raw,pos,0xffffffff);struct.pack_into('<I',raw,24,pos+8)
    struct.pack_into('<I',raw,44,number)
    raw[48:54]=b'\xaa\xbb'+raw[510:512]+raw[1022:1024]
    raw[510:512]=raw[1022:1024]=b'\xaa\xbb'
    return bytes(raw)


def mft_file(path,**kwargs):
    path.write_bytes(mft_record(0,names=('$MFT',))+bytes(4096)+mft_record(5,names=('.',),directory=True)+mft_record(**kwargs))
    return path


def prefetch_file(path,name='PAYLOAD.EXE',version=17):
    info_end=152 if version==17 else 240 if version==23 else 304
    metrics_size=20 if version==17 else 32
    filenames=('C:\\Temp\\'+name+'\x00').encode('utf-16le')
    size=info_end+metrics_size+len(filenames)+8
    raw=bytearray(size)
    struct.pack_into('<I4sII',raw,0,version,b'SCCA',0,size)
    encoded=name.encode('utf-16le');raw[16:16+len(encoded)]=encoded
    struct.pack_into('<I',raw,76,0x1234)
    struct.pack_into('<IIIIIIIII',raw,84,info_end,1,0,0,info_end+metrics_size,len(filenames),0,0,0)
    struct.pack_into('<IIIII',raw,info_end,0,0,0,len(filenames)//2-1,0)
    if version!=17:struct.pack_into('<IIIIII',raw,info_end,0,0,0,0,len(filenames)//2-1,0)
    raw[info_end+metrics_size:info_end+metrics_size+len(filenames)]=filenames
    struct.pack_into('<Q',raw,120 if version==17 else 128,FT)
    struct.pack_into('<I',raw,144 if version==17 else 152 if version==23 else 208,17)
    path.write_bytes(raw);return path


def registry_file(path,dirty=False,target=r'C:\Temp\payload.exe'):
    cells=bytearray(32)
    def cell(data):
        offset=len(cells);size=(len(data)+4+7)//8*8
        cells.extend(struct.pack('<i',-size)+data+bytes(size-4-len(data)))
        return offset
    def value(name,typ,data):
        encoded=name.encode('ascii')
        pointer=cell(data) if len(data)>4 else int.from_bytes(data.ljust(4,b'\x00'),'little')
        return cell(struct.pack('<2sHIIIHH',b'vk',len(encoded),len(data)|(0x80000000 if len(data)<=4 else 0),pointer,typ,1,0)+encoded)
    def key(name,children=(),values=(),root=False):
        sub=cell(b'li'+struct.pack('<H',len(children))+b''.join(struct.pack('<I',v) for v in children)) if children else 0xffffffff
        vals=cell(b''.join(struct.pack('<I',v) for v in values)) if values else 0xffffffff
        encoded=name.encode('ascii');data=bytearray(76+len(encoded))
        struct.pack_into('<2sHQ',data,0,b'nk',0x20|(2 if root else 0),FT)
        struct.pack_into('<IIIIIIII',data,16,0xffffffff,len(children),0,sub,0xffffffff,len(values),vals,0xffffffff)
        struct.pack_into('<I',data,48,0xffffffff);struct.pack_into('<HH',data,72,len(encoded),0);data[76:]=encoded
        return cell(data)
    run=key('Run',values=[value('Example',1,(target+'\x00').encode('utf-16le')),value('Binary',3,b'\x00\xff\x1b\x00')])
    explorer=key('Explorer')
    current=key('CurrentVersion',[run,explorer]);windows=key('Windows',[current]);microsoft=key('Microsoft',[windows])
    software=key('Software',[microsoft]);root=key('ROOT',[software],root=True)
    total=(len(cells)+4095)//4096*4096
    free=total-len(cells)
    if free:cells.extend(struct.pack('<i',free)+bytes(free-4))
    struct.pack_into('<4sII',cells,0,b'hbin',0,total)
    header=bytearray(4096);struct.pack_into('<4sIIQIIIIIII',header,0,b'regf',1,2 if dirty else 1,FT,1,5,0,1,root,total,1)
    checksum=0
    for i in range(0,508,4):checksum^=struct.unpack_from('<I',header,i)[0]
    struct.pack_into('<I',header,508,checksum)
    path.write_bytes(header+cells);return path


def evtx_process(db,offset=1,path=r'C:\Temp\PAYLOAD.EXE',host='host',delta=0,parent=None):
    from forensic_assistant.database.db import register_source,insert_events
    from forensic_assistant.ingest.normalize import normalize
    from forensic_assistant.artifacts.times import filetime
    from forensic_assistant.retrieval.evidence import get_evidence
    from test_ingest import xml,SHA
    stamp=filetime(FT+delta,'x','x','x')['timestamp_utc']
    data=f'<Data Name="NewProcessName">{path}</Data><Data Name="NewProcessId">10</Data>'
    if parent:data+=f'<Data Name="ParentProcessName">{parent}</Data>'
    raw=xml(data=data).replace('2026-09-15T14:30:55.1234567Z',stamp).replace('PC.example',host)
    event=normalize(raw,SHA,'synthetic.evtx',offset)
    with db:register_source(db,SHA,1,'synthetic.evtx');insert_events(db,[event])
    return get_evidence(db,event.id)
