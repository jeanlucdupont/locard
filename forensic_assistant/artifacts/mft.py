"""Dissect performs binary decoding/fixups; Locard preserves slots and semantics."""
import base64
import io
from functools import lru_cache
from forensic_assistant.artifacts.storage import base_record
from forensic_assistant.artifacts.times import filetime
from forensic_assistant.database.artifacts import add_object,dump

PARSER='dissect.ntfs'


def parse(path,sha,record_size=None):
    from dissect.ntfs.mft import MftRecord
    from dissect.ntfs.attr import Attribute,AttributeHeader
    from dissect.ntfs.c_ntfs import c_ntfs
    with open(path,'rb') as fh:
        first=fh.read(64)
        if record_size is None:
            if first[:4]!=b'FILE':raise ValueError('MFT header invalid; record framing cannot be established')
            record_size=int(c_ntfs._FILE_RECORD_SEGMENT_HEADER(first).BytesAllocated)
        if record_size not in (512,1024,2048,4096,8192,16384,32768,65536):raise ValueError('Unsupported MFT record size')
        fh.seek(0);offset=0
        while raw:=fh.read(record_size):
            locator={'offset':offset,'length':len(raw)}
            eid=f'MFT:{sha}:Offset:{offset}'
            try:
                if len(raw)!=record_size:raise ValueError('Truncated MFT record')
                if not any(raw):offset+=record_size;continue
                r=MftRecord.from_bytes(raw);h=r.header
                if h.BytesAllocated!=record_size or not 0<h.BytesInUse<=record_size:raise ValueError('Invalid MFT record bounds')
                warnings=[];attrs=[];names=[];stamps=[];size=None
                pos=h.FirstAttributeOffset;stream=io.BytesIO(r.data);terminated=False
                while pos+4<=h.BytesInUse:
                    # The end marker is four bytes, not a full attribute header.
                    if r.data[pos:pos+4]==b'\xff\xff\xff\xff':terminated=True;break
                    aheader=AttributeHeader(stream,pos,r)
                    if int(aheader.type)==0xffffffff:terminated=True;break
                    if aheader.record_length<24 or pos+aheader.record_length>h.BytesInUse:raise ValueError('Invalid MFT attribute bounds')
                    a=Attribute(aheader,r);slot=f'attribute:{pos}';kind=int(aheader.type)
                    attrs.append(dict(type=kind,offset=pos,instance=int(aheader.header.Instance),name=aheader.name,
                                      resident=aheader.resident,flags=int(aheader.flags),size=aheader.size))
                    if kind in (16,48):
                        info=a.attribute.attr
                        prefix='SI' if kind==16 else 'FN'
                        for field,label in (('CreationTime','Created'),('LastModificationTime','Modified'),('LastChangeTime','MFTChanged'),('LastAccessTime','Accessed')):
                            stamps.append(filetime(int(getattr(info,field)),slot+':'+label,f'MFT {prefix} {label}',f'Filesystem metadata {prefix} {label} timestamp'))
                        if kind==48:
                            parent=info.ParentDirectory
                            names.append(dict(slot=slot,filename=a.attribute.file_name,namespace=int(info.Flags),
                                              parent_record=int(parent.SegmentNumberLowPart)+(int(parent.SegmentNumberHighPart)<<32),
                                              parent_sequence=int(parent.SequenceNumber)))
                    if kind==128 and not aheader.name:size=aheader.size
                    if kind==32:warnings.append('Attribute-list extensions are separate records; external/nonresident content is not reconstructed')
                    pos+=aheader.record_length
                if not terminated:raise ValueError('Missing MFT attribute terminator')
                base=h.BaseFileRecordSegment
                detail=dict(record_number=offset//record_size,sequence_number=int(h.SequenceNumber),allocated=bool(h.Flags&1),
                            directory=bool(h.Flags&2),file_size=size,base_record=int(base.SegmentNumberLowPart)+(int(base.SegmentNumberHighPart)<<32),
                            base_sequence=int(base.SequenceNumber),record_size=record_size,attributes=attrs,names=names,
                            raw=base64.b64encode(raw).decode())
                yield dict(record=base_record(eid,'mft','mft_record',locator,warnings),detail=detail,timestamps=stamps)
            except Exception as exc:
                yield {'error':f'{type(exc).__name__}: {exc}','locator':locator}
            offset+=record_size


def reconstruct_paths(db,sha,max_depth=128,max_paths=32):
    """Disk-backed parent resolution; sequence mismatches never produce full paths."""
    prefix=f'MFT:{sha}:Offset:'
    @lru_cache(maxsize=4096)
    def record(number):
        return db.execute('SELECT * FROM mft_records WHERE evidence_id=?',(prefix+str(number*record_size),)).fetchone()
    @lru_cache(maxsize=4096)
    def names(eid):return tuple(db.execute('SELECT * FROM mft_names WHERE evidence_id=? ORDER BY slot',(eid,)))
    first=db.execute('SELECT record_size FROM mft_records WHERE evidence_id LIKE ? LIMIT 1',(prefix+'%',)).fetchone()
    if not first:return
    record_size=first[0]
    def parent_paths(number,sequence,seen):
        if number in seen:return [],'cycle'
        if len(seen)>=max_depth:return [],'depth_limit'
        parent=record(number)
        if not parent or parent['sequence_number']!=sequence:return [],'missing_or_reused_parent'
        if not parent['directory']:return [],'parent_not_directory'
        if number==5:return [''],'volume_relative'
        paths=[];status='missing_parent_name'
        for n in names(parent['evidence_id']):
            roots,status=parent_paths(n['parent_record'],n['parent_sequence'],seen|{number})
            paths.extend(root+'\\'+n['filename'] for root in roots)
            if len(paths)>max_paths:return [],'path_limit'
        return sorted(set(paths)),status
    cursor=db.execute('SELECT n.*,r.record_number FROM mft_names n JOIN mft_records r USING(evidence_id) WHERE n.evidence_id LIKE ? ORDER BY n.evidence_id,n.slot',(prefix+'%',))
    while rows:=cursor.fetchmany(500):
        for n in rows:
            roots,status=parent_paths(n['parent_record'],n['parent_sequence'],{n['record_number']}) if n['record_number']!=5 else ([''],'volume_relative')
            paths=[root+'\\'+n['filename'] for root in roots] if n['record_number']!=5 else ['\\']
            db.execute('UPDATE mft_names SET reconstructed_path=?,path_status=? WHERE evidence_id=? AND slot=?',
                       (paths[0] if len(paths)==1 else None,'multiple_paths' if len(paths)>1 else status,n['evidence_id'],n['slot']))
            if not paths:add_object(db,n['evidence_id'],n['slot'],'filename',n['filename'])
            for i,p in enumerate(paths):add_object(db,n['evidence_id'],n['slot']+f':path:{i}','file_path',p)
