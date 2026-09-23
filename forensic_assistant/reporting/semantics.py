"""Locard-owned timeline labels; evidence values never supply HTML or conclusions."""
def timestamp_label(source):
    labels={'EVTX SystemTime':'Event timestamp',
            'Prefetch LastRun':'Recorded execution timestamp; not a process-instance identifier',
            'Registry Key LastWrite':'Key last-write timestamp; not individual value creation'}
    for prefix in ('SI','FN'):
        for label in ('Created','Modified','MFTChanged','Accessed'):
            labels[f'MFT {prefix} {label}']=f'Filesystem metadata {prefix} {label} timestamp'
    if source in labels: return source,labels[source]
    return 'Timestamp observation','Semantics suppressed; inspect original evidence'
