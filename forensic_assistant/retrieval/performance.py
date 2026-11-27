"""Optional content-free phase timings; no evidence cache or disclosure authority."""
from functools import wraps
from time import monotonic

def measured(phase):
    def decorate(fn):
        @wraps(fn)
        def call(self,*args,**kwargs):
            started=monotonic()
            try:return fn(self,*args,**kwargs)
            finally:
                if self.profile is not None:self.profile.append(dict(phase=phase,seconds=monotonic()-started))
        return call
    return decorate
