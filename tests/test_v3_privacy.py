import subprocess
import sys
from pathlib import Path

def test_deterministic_imports_without_semantic_dependencies():
    code='''
import sys,importlib.abc
class Block(importlib.abc.MetaPathFinder):
 def find_spec(self,fullname,path=None,target=None):
  if fullname.split('.')[0] in ('torch','numpy','faiss','sentence_transformers','transformers','huggingface_hub'):
   raise ImportError('Semantic dependency intentionally unavailable')
sys.meta_path.insert(0,Block())
from forensic_assistant.cli import main
from forensic_assistant.database.db import connect
from forensic_assistant.llm.ask import ask
from forensic_assistant.retrieval.queries import Queries
db=connect(':memory:')
assert ask(Queries(db),'PowerShell',dry_run=True)['status']=='insufficient_evidence'
'''
    subprocess.run([sys.executable,'-c',code],check=True,capture_output=True)

def test_sensitive_paths_are_ignored():
    root=Path(__file__).parents[1]
    paths=['forensic_assistant/artifacts/secrets.py','forensic_assistant/artifacts/credentials.py',
      'data/case.db','models/model.safetensors','case.db.semantic-index/CURRENT','semantic-models/bge/config.json']
    result=subprocess.run(['git','check-ignore','--no-index',*paths],cwd=root,text=True,capture_output=True)
    assert set(result.stdout.splitlines())==set(paths)
    source=subprocess.run(['git','check-ignore','--no-index','forensic_assistant/artifacts/worker.py','LICENSE'],cwd=root,text=True,capture_output=True)
    assert source.returncode==1
