"""Read-only libscca extraction, including raw FILETIME execution slots."""
import base64
from pathlib import Path
from forensic_assistant.artifacts.storage import base_record
from forensic_assistant.artifacts.times import filetime

MAX_FILE=64*1024*1024


def parse(path,sha):
    import pyscca
    if Path(path).stat().st_size>MAX_FILE:raise ValueError('Prefetch file exceeds 64 MiB limit')
    with open(path,'rb') as stream:
        head=stream.read(8);stream.seek(0)
        if head[:3]==b'MAM' and int.from_bytes(head[4:8],'little')>MAX_FILE:
            raise ValueError('Prefetch decompressed size exceeds 64 MiB limit')
        f=pyscca.open_file_object(stream)
        try:
            version=f.format_version
            if version not in (17,23,26,30,31):raise ValueError('Unsupported Prefetch version')
            if f.number_of_filenames>100000 or f.number_of_volumes>1024:raise ValueError('Prefetch collection limit exceeded')
            eid=f'PREFETCH:{sha}:File'
            stamps=[filetime(f.get_last_run_time_as_integer(i),f'run:{i}','Prefetch LastRun',
                             'Recorded execution timestamp; not a process-instance identifier') for i in range(1 if version in (17,23) else 8)]
            if f.number_of_file_metrics_entries>100000:raise ValueError('Prefetch metrics limit exceeded')
            references=list(f.filenames);volumes=[]
            metrics=[dict(filename=m.filename,file_reference=m.file_reference) for m in f.file_metrics_entries]
            for v in f.volumes:
                volumes.append(dict(device_path=v.device_path,serial_number=v.serial_number,creation_filetime=str(v.get_creation_time_as_integer())))
            warnings=['Prefetch identifier is not a content hash','Run count and retained execution slots are not a complete execution history',
                      'Missing Prefetch does not establish non-execution; collection may be disabled or deleted',
                      'Referenced files are not all executed images; directory tables are not exposed by this binding']
            detail=dict(executable=f.executable_filename,prefetch_identifier=f.prefetch_hash,run_count=f.run_count,
                        format_version=version,references=references,volumes=volumes,metrics=metrics,raw=base64.b64encode(Path(path).read_bytes()).decode())
            import ntpath
            objects=[dict(slot='executable',role='executable_name',original=f.executable_filename)] if f.executable_filename else []
            for i,reference in enumerate(references):
                role='executable_path_candidate' if f.executable_filename and ntpath.basename(reference).lower()==f.executable_filename.lower() else 'referenced_file'
                objects.append(dict(slot=f'reference:{i}',role=role,original=reference))
            yield dict(record=base_record(eid,'prefetch','prefetch_file',{'offset':0,'length':Path(path).stat().st_size},warnings),
                       detail=detail,timestamps=stamps,objects=objects)
        finally:f.close()
