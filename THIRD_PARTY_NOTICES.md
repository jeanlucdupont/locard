# Third-party licensing

Locard's original project source is licensed under Apache License 2.0; see LICENSE.
Third-party components retain their own licenses. This declaration does not
relicense dependencies, model weights, or forensic input files.

Existing dependencies include python-evtx (Apache-2.0), defusedxml (PSF),
dissect.cstruct and dissect.util (Apache-2.0), dissect.ntfs (AGPL-3.0-or-later),
libscca-python and libregf-python (LGPL-3.0-or-later), and hexdump (public domain).

In particular, Apache licensing of Locard source does not remove the AGPL
obligations associated with distributing a combined application using
dissect.ntfs. Do not describe the complete dependency bundle as Apache-only.
LGPL components likewise retain their redistribution requirements. Dependency
license texts must remain unchanged and accompany distributions as required.

V3 dependency validation and the selected model's immutable revision and file
hashes are recorded separately. Model and index files are not source artifacts.

## V3 optional stack

| Component | Validated version | Upstream license |
|---|---|---|
| BGE-small-en-v1.5 | revision in V3.md | MIT |
| all-MiniLM-L6-v2 (evaluation candidate) | revision in V3.md | Apache-2.0 |
| sentence-transformers | 5.7.0 | Apache-2.0 |
| faiss-cpu | 1.14.3 | MIT |
| transformers | 5.17.0 | Apache-2.0 |
| huggingface-hub | 1.32.0 | Apache-2.0 |
| tokenizers | 0.23.2 | Apache-2.0 |
| safetensors | 0.8.0 | Apache-2.0 |
| torch | 2.14.0 | BSD and bundled permissive components; retain wheel notices |
| numpy | 2.5.3 | BSD-3-Clause and bundled permissive components |
| scipy | 1.18.1 | BSD-3-Clause and bundled component notices |
| scikit-learn | 1.9.1 | BSD-3-Clause |

These V3 licenses permit use alongside Apache-2.0 project source, subject to
their attribution and redistribution obligations. This does not override existing
AGPL/LGPL requirements. Preserve wheel/package license files and model licenses
when distributing dependencies or weights. No third-party license text is edited
or replaced by Locard's LICENSE file.

The resolved V3 dependency graph was also inspected, including transitive wheels.
certifi 2026.7.22 uses MPL-2.0; tqdm 4.70.1 uses MPL-2.0 AND MIT. MPL-covered
files retain their notices and source-availability obligations when redistributed;
they are not relicensed Apache-2.0. Combining separate MPL-covered files with
Apache-licensed project files is supported by MPL's file-level boundary; see
the [Mozilla MPL FAQ](https://www.mozilla.org/en-US/MPL/2.0/FAQ/).

Other resolved components retain their published licenses: Jinja2, MarkupSafe,
Pygments, click, cloudpickle, colorama, fsspec, httpcore, httpx, idna, joblib,
mpmath, networkx, sympy and threadpoolctl (BSD family); PyYAML, annotated-doc,
anyio, filelock, h11, markdown-it-py, mdurl, narwhals, rich, setuptools and typer
(MIT); hf-xet (Apache-2.0); packaging (Apache-2.0 OR BSD-2-Clause); shellingham
(ISC); typing_extensions (PSF-2.0); regex (Apache-2.0 AND CNRI-Python).
Retain bundled NumPy/SciPy/Torch component notices as well. No new V3 dependency
requires relicensing Locard's original source under a different license; this
does not remove any component-specific distribution obligations.
