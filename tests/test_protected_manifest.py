import importlib.util
import hashlib
from pathlib import Path
import pytest

spec=importlib.util.spec_from_file_location('protected_manifest',Path(__file__).parents[1]/'scripts/protected_manifest.py')
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_manifest_exact_hash_order_and_no_modification(tmp_path):
    (tmp_path/'b').write_bytes(b'123');(tmp_path/'a').write_bytes(b'abc')
    before={p.name:p.stat().st_mtime_ns for p in tmp_path.iterdir()}
    manifest=module.create(tmp_path,['b','a'])
    assert manifest['files']==[{'path':'a','size':3,'sha256':hashlib.sha256(b'abc').hexdigest()},
                               {'path':'b','size':3,'sha256':hashlib.sha256(b'123').hexdigest()}]
    assert not manifest['historical_claim']
    assert module.verify(tmp_path,manifest)==[]
    assert before=={p.name:p.stat().st_mtime_ns for p in tmp_path.iterdir()}
    (tmp_path/'a').write_bytes(b'xyz')  # Equal size is not sufficient.
    assert module.verify(tmp_path,manifest)==['a']
    (tmp_path/'b').unlink()
    assert module.verify(tmp_path,manifest)==['a','b']

@pytest.mark.parametrize('path',['../escape','C:/escape','/absolute','dir\\file'])
def test_manifest_rejects_unsafe_paths(tmp_path,path):
    with pytest.raises(ValueError):module.create(tmp_path,[path])


def test_manifest_rejects_duplicate_paths(tmp_path):
    with pytest.raises(ValueError):module.create(tmp_path,['a','a'])
