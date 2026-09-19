"""CLI registration uses only the standard library until a semantic operation."""
from pathlib import Path

def configure(commands,ask):
    ask.add_argument('--semantic-index')
    ask.add_argument('--embedding-model')
    semantic=commands.add_parser('semantic',help='Explicit local semantic retrieval (optional dependencies)')
    sub=semantic.add_subparsers(dest='semantic_command',required=True)
    setup=sub.add_parser('setup',help='Explicitly download pinned model files; no evidence is read')
    setup.add_argument('destination');setup.add_argument('--model',choices=['bge','minilm'],default='bge')
    for name in ('build','rebuild','status','search'):
        p=sub.add_parser(name);p.add_argument('--index');p.add_argument('--model-path')
        if name in ('build','rebuild'):p.add_argument('--max-vectors',type=int,default=100000)
        if name=='search':
            p.add_argument('question');p.add_argument('--limit',type=int,default=20)
            for f in ('artifact','start','end','hostname','user','path'):p.add_argument('--'+f)

def dispatch(db,args):
    from .index import build,status,search,default_root
    from .model import LocalModel
    root=args.index or default_root(args.db)
    if args.semantic_command=='status':return status(db,root)
    model=LocalModel(args.model_path or Path(args.db).parent/'semantic-models'/'bge')
    if args.semantic_command in ('build','rebuild'):
        return build(db,root,model,rebuild=args.semantic_command=='rebuild',max_vectors=args.max_vectors)
    filters={name:getattr(args,name) for name in ('artifact','start','end','hostname','path') if getattr(args,name)}
    if args.hostname:filters['strict_host']=True
    if args.user:filters['username']=args.user
    return search(db,root,model,args.question,limit=args.limit,**filters)
