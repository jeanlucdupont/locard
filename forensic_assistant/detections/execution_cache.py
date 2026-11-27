"""Worker-owned, read-view-bound completed populations; no evidence authority."""
from collections import OrderedDict
import hashlib
import json
import sys
import time

CACHE_BYTES=256*1024*1024  # Retention budget, 1/8 of the existing 2-GiB worker cap.
RANKING_VERSION='execution-ranking-v1'

def canonical(value):return json.dumps(value,sort_keys=True,ensure_ascii=True,separators=(',',':'))

def retained_size(value,check=lambda:None):
    seen=set();stack=[value];total=0
    while stack:
        check();v=stack.pop();identity=id(v)
        if identity in seen:continue
        seen.add(identity);total+=sys.getsizeof(v)
        if isinstance(v,dict):stack.extend(v.keys());stack.extend(v.values())
        elif isinstance(v,(list,tuple,set,frozenset)):stack.extend(v)
    return total

class PopulationCache:
    def __init__(self,view,scope,*,budget=CACHE_BYTES):
        self.view=view;self.scope=canonical(scope);self.binding=canonical(view.state)
        self.entries=OrderedDict();self.bytes=0;self.budget=budget
        self.evictions=0;self.invalidations=0

    def clear(self,*,invalid=False):
        self.entries.clear();self.bytes=0
        if invalid:self.invalidations+=1

    def validate(self,db,scope):
        try:
            self.view.check_identity()
            if db is not self.view.db or canonical(self.view.state)!=self.binding or canonical(scope)!=self.scope:
                raise ValueError('Behavioral population authority changed')
        except BaseException:
            self.clear(invalid=True);raise

    def resolve(self,db,scope,key,build,check=lambda:None):
        self.validate(db,scope);check()
        identity=hashlib.sha256(canonical([self.binding,self.scope,key]).encode()).hexdigest()
        hit=identity in self.entries;started=time.monotonic()
        if hit:
            data,size=self.entries.pop(identity);self.entries[identity]=(data,size)
        else:
            try:
                data=build();check();self.validate(db,scope)
                size=retained_size(data,check)
                while self.entries and self.bytes+size>self.budget:
                    _,(_,old)=self.entries.popitem(last=False);self.bytes-=old;self.evictions+=1
                if size<=self.budget:self.entries[identity]=(data,size);self.bytes+=size
            except BaseException:
                self.clear();raise
        return data,dict(population_id=identity,status='reused' if hit else 'constructed',cache_hit=hit,
            retained=identity in self.entries,retained_population_bytes=size,retained_cache_bytes=self.bytes,
            cache_budget_bytes=self.budget,evictions=self.evictions,invalidations=self.invalidations,
            construction_seconds=0.0 if hit else time.monotonic()-started)
