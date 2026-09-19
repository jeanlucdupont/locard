"""Explicit setup; investigation loading is local-only and uses reviewed modules."""
import hashlib
import json
import os
import importlib.metadata
from pathlib import Path

MODELS={
 'bge':('BAAI/bge-small-en-v1.5','5c38ec7c405ec4b44b94cc5a9bb96e735b38267a'),
 'minilm':('sentence-transformers/all-MiniLM-L6-v2','1110a243fdf4706b3f48f1d95db1a4f5529b4d41'),
}
FILES=('config.json','config_sentence_transformers.json','modules.json','sentence_bert_config.json',
       'special_tokens_map.json','tokenizer.json','tokenizer_config.json','vocab.txt','model.safetensors','1_Pooling/config.json','README.md','LICENSE')


def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as stream:
        while value:=stream.read(1024*1024):h.update(value)
    return h.hexdigest()


def setup(destination,model='bge'):
    """The only network-enabled semantic operation. Never receives case text."""
    import urllib.request
    root=Path(destination)
    if root.exists():raise ValueError('Model destination already exists; choose an empty destination')
    model_id,revision=MODELS[model];root.mkdir(parents=True)
    hashes={}
    for name in FILES:
        url='https://huggingface.co/'+model_id+'/resolve/'+revision+'/'+name
        try:response=urllib.request.urlopen(url,timeout=60)
        except urllib.error.HTTPError as exc:
            if exc.code==404 and name not in ('config.json','modules.json','tokenizer.json','model.safetensors','1_Pooling/config.json'):continue
            raise ValueError('Model setup failed; incomplete directory is not usable') from exc
        path=root/name;path.parent.mkdir(parents=True,exist_ok=True)
        total=0
        with response,path.open('xb') as stream:
            while value:=response.read(1024*1024):
                total+=len(value)
                if total>200*1024*1024:raise ValueError('Model file exceeds setup limit')
                stream.write(value)
        hashes[name]=sha(path)
    manifest={'model_id':model_id,'revision':revision,'files':hashes}
    (root/'locard-model.json').write_text(json.dumps(manifest,sort_keys=True,indent=2),encoding='utf-8')
    return manifest


class LocalModel:
    dimension=384
    def __init__(self,path):
        root=Path(path)
        try:
            manifest_path=root/'locard-model.json'
            if manifest_path.stat().st_size>32768:raise ValueError('Oversized model manifest')
            self.manifest=json.loads(manifest_path.read_text(encoding='utf-8'))
            if (self.manifest['model_id'],self.manifest['revision']) not in MODELS.values():raise ValueError('Unapproved model revision')
            for name,digest in self.manifest['files'].items():
                if name not in FILES or sha(root/name)!=digest:raise ValueError('Model file integrity mismatch')
            if not {'config.json','modules.json','tokenizer.json','model.safetensors','1_Pooling/config.json'}<=self.manifest['files'].keys():raise ValueError('Incomplete model')
            modules=json.loads((root/'modules.json').read_text())
            expected=[('','sentence_transformers.models.Transformer'),('1_Pooling','sentence_transformers.models.Pooling')]
            # Some reviewed snapshots contain a parameter-free Normalize module.
            actual=[(m['path'],m['type']) for m in modules]
            if actual not in (expected,expected+[('2_Normalize','sentence_transformers.models.Normalize')]):raise ValueError('Unapproved model module configuration')
        except (OSError,KeyError,TypeError,AttributeError,json.JSONDecodeError) as exc:
            raise ValueError('Local model unavailable or malformed; run explicit semantic setup') from exc
        os.environ['HF_HUB_OFFLINE']='1';os.environ['TRANSFORMERS_OFFLINE']='1'
        os.environ['HF_HUB_DISABLE_TELEMETRY']='1';os.environ['DO_NOT_TRACK']='1'
        try:
            import torch
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:raise ValueError('Install Locard optional semantic dependencies first') from exc
        torch.set_num_threads(4)
        self.model=SentenceTransformer(str(root.resolve()),device='cpu',local_files_only=True,
          trust_remote_code=False,model_kwargs={'use_safetensors':True})
        self.document_limit=min(512,self.model.max_seq_length)
        self.identity={**{k:self.manifest[k] for k in ('model_id','revision','files')},
          'dimension':384,'normalization':'l2','backend':'sentence-transformers-cpu','document_limit':self.document_limit}
        self.identity['packages']={n:importlib.metadata.version(n) for n in ('sentence-transformers','torch','transformers','tokenizers','numpy','faiss-cpu')}
        self.prefix='Represent this sentence for searching relevant passages: ' if self.manifest['model_id'].startswith('BAAI/') else ''

    def count(self,text):
        return len(self.model.tokenizer.encode(text,add_special_tokens=True,truncation=False))

    def encode(self,texts,query=False):
        if len(texts)>16 or any(len(t)>8192 for t in texts):raise ValueError('Embedding batch/input limit exceeded')
        texts=[self.prefix+t if query else t for t in texts]
        if any(self.count(t)>self.document_limit for t in texts):raise ValueError('Embedding token limit exceeded')
        return self.model.encode(texts,batch_size=16,normalize_embeddings=True,convert_to_numpy=True,show_progress_bar=False)
