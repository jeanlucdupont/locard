"""Fixed, parameterized browser predicates over normalized case records."""
from forensic_assistant.artifacts.paths import normalize_path


def filters(artifact, url, url_contains, title, title_contains, download_path, download_path_contains, browser, profile, browser_kind=None):
    requested = (url, url_contains, title, title_contains, download_path, download_path_contains, browser, profile, browser_kind)
    if not any(value is not None for value in requested):
        return [], []
    if artifact not in (None, 'browser'):
        raise ValueError('Browser filters require --artifact browser or no --artifact')
    clauses, params = ["e.source_type='browser'"], []
    if browser_kind is not None:
        if browser_kind not in ('visit', 'download'):
            raise ValueError('Browser kind must be visit or download')
        clauses.append('e.artifact_type=?')
        params.append('browser_' + browser_kind)
    for field, exact, contains in [('url', url, url_contains), ('title', title, title_contains)]:
        if exact is not None and contains is not None:
            raise ValueError('Exact and contains browser filters are mutually exclusive')
        value = exact if exact is not None else contains
        if value is None:
            continue
        if not value:
            raise ValueError('Browser search value must not be empty')
        expression = "json_extract(e.original_json,'$." + field + "')"
        comparison = expression + '=?' if exact is not None else 'instr(' + expression + ',?)>0'
        if field == 'url':
            chain = "json_extract(j.value,'$.url')"
            chain_comparison = chain + '=?' if exact is not None else 'instr(' + chain + ',?)>0'
            comparison = '(' + comparison + " OR EXISTS (SELECT 1 FROM json_each(e.original_json,'$.url_chain') j WHERE " + chain_comparison + '))'
            params.append(value)
        clauses.append(comparison)
        params.append(value)
    if download_path is not None or download_path_contains is not None:
        if download_path is not None and download_path_contains is not None:
            raise ValueError('Exact and contains download-path filters are mutually exclusive')
        value = download_path if download_path is not None else download_path_contains
        if not value:
            raise ValueError('Download path must not be empty')
        comparison = 'o.normalized=?' if download_path is not None else 'instr(lower(o.original),lower(?))>0'
        clauses.append("EXISTS (SELECT 1 FROM evidence_objects o WHERE o.evidence_id=e.evidence_id AND o.role IN ('download_target','download_path') AND " + comparison + ')')
        params.append(normalize_path(value)['normalized'] if download_path is not None else value)
    for field, value in [('browser_product', browser), ('profile', profile)]:
        if value is not None:
            clauses.append("json_extract(e.original_json,'$." + field + "')=?")
            params.append(value)
    return clauses, params
