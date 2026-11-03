"""Editorial decisions never validate AI references or authorize evidence retrieval."""
import copy

LIMITED_STATEMENT = ('AI-proposed briefing draft with unresolved source references. '
                     'This annotation is not an original analyst statement or verified provenance.')


def references(summary, inventory, exposed):
    ids=summary.get('source_ids') or []
    known={u['id'] for u in inventory};shown={u['id'] for u in exposed}
    details=[{'id':sid,'status':'exposed' if sid in shown else 'not_exposed' if sid in known else 'unknown_source_id'} for sid in ids]
    valid=bool(ids) and all(d['status']=='exposed' for d in details)
    return {'status':'validated_references' if valid else 'missing_references' if not ids else 'unresolved_references',
            'references':details,'semantic_faithfulness':'not_verified'}


def proposal(summary, validation):
    return {'origin':'ai','decision':'pending','source_validation':copy.deepcopy(validation),
            'original_draft':{k:copy.deepcopy(summary[k]) for k in ('text','uncertainty','source_ids') if k in summary},
            'acknowledged_unvalidated':False,'forensic_verification':'not_performed'}


def needs_ack(review):
    return (review.get('source_validation',{}).get('status')!='validated_references' and
            not review.get('acknowledged_unvalidated') and review.get('decision') not in ('rejected','omitted'))


def approve(review, read):
    if needs_ack(review):
        from .briefing_workflow import read_answer
        answer=read_answer(read,'Summary provenance is not fully validated. Accept it as an analyst-reviewed briefing only? [y/N]: ')
        if answer.strip().lower() not in ('y','yes'):return False
        review['acknowledged_unvalidated']=True
    review['decision']='accepted'
    return True



def exchange_schema():
    from .briefing_canonical import DOCUMENT
    from .investigation_ai.contracts import obj,enumeration,string
    review=obj({'decision':enumeration('pending','accepted','rejected','omitted'),
        'source_status':enumeration('validated_references','missing_references','unresolved_references','not_validated_import'),
        'original_text':string(700),'original_uncertainty':string(300),
        'edited_text':{'type':'string','minLength':0,'maxLength':1200},
        'acknowledgment':enumeration('acknowledged','not_acknowledged')},
        ('decision','source_status','original_text','original_uncertainty','edited_text','acknowledgment'))
    return obj({'format':{'type':'integer','minimum':2,'maximum':2},'document':DOCUMENT,'summary_review':review},
               ('format','document','summary_review'))


def export_document(document, original):
    review=original.get('summary_editorial')
    if not review:return document
    draft=review['original_draft']
    return {'format':2,'document':document,'summary_review':{
        'decision':review['decision'],'source_status':review.get('imported_source_status',review['source_validation']['status']),
        'original_text':draft['text'],'original_uncertainty':draft['uncertainty'],
        'edited_text':review.get('edited_text',''),
        'acknowledgment':'acknowledged' if review['acknowledged_unvalidated'] else 'not_acknowledged'}}


def import_document(value):
    from .briefing_canonical import validate_document,check
    if isinstance(value,dict) and value.get('format')==2:
        validate_document(value,exchange_schema())
        document=check(value['document']);saved=value['summary_review']
        review=proposal({'text':saved['original_text'],'uncertainty':saved['original_uncertainty']},
                        {'status':'not_validated_import','references':[],'semantic_faithfulness':'not_verified'})
        review.update(imported_source_status=saved['source_status'],imported_decision=saved['decision'],
                      imported_acknowledgment=saved['acknowledgment'],edited_text=saved['edited_text'])
        if document['summary']['status']=='rejected':review['decision']='rejected'
        elif not document['summary']['text']:review['decision']='omitted'
        return document,{'summary_editorial':review}
    return check(value),{}
