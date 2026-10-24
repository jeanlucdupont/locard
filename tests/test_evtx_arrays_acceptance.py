"""Opt-in read-only acceptance checks. Real evidence is never a repository fixture.

Set LOCARD_EVTX_ACCEPTANCE_DIR to the authorized sample-copy directory on Windows.
"""
import os
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
from Evtx.Evtx import Evtx
from forensic_assistant.ingest import evtx_arrays as compat

ROOT = os.environ.get('LOCARD_EVTX_ACCEPTANCE_DIR')
pytestmark = pytest.mark.skipif(not ROOT or os.name != 'nt', reason='Requires authorized Windows EVTX copies')


@pytest.mark.parametrize('name,number,offset,type_,size,field', [
    ('Intel-Gfx-Display-External%4GfxDisplayExEventViewer.evtx', 101611, 4608, 0x84, 4, 'BDF'),
    ('Microsoft-Windows-Ntfs%4Operational.evtx', 31646, 135680, 0x88, 4, 'CachedRunsAlignment'),
    ('Microsoft-Windows-Ntfs%4Operational.evtx', 31606, 20768, 0x8a, 128, 'ExtentsCountArray'),
    ('Microsoft-Windows-Ntfs%4Operational.evtx', 31646, 135680, 0x86, 2, 'RunsInCachedRuns'),
    ('Microsoft-Windows-Ntfs%4Operational.evtx', 31646, 135680, 0x86, 2, 'MostPopulatedBinCountInCachedRuns'),
    ('System.evtx', 74233, 28816, 0x94, 16, 'Reg'),
    ('Microsoft-Windows-Hyper-V-Hypervisor-Admin.evtx', 2, 6368, 0x95, 16, 'ProcessorFeatures'),
])
def test_windows_array_equivalence(monkeypatch, name, number, offset, type_, size, field):
    path = Path(ROOT) / name
    raw = subprocess.run(['wevtutil', 'qe', str(path), '/lf:true',
                          '/q:*[System[EventRecordID=' + str(number) + ']]',
                          '/c:1', '/f:xml', '/uni:true'], check=True, capture_output=True, timeout=30).stdout
    windows = ET.fromstring(raw)
    expected = [n.text or '' for n in windows.findall('.//{*}Data') if n.get('Name') == field]
    assert expected
    captured = []
    original = compat.NumericArray.__init__

    def capture(self, buf, at, length, kind, lower, upper):
        original(self, buf, at, length, kind, lower, upper)
        if kind == type_:
            captured.append((length, list(self.values)))

    monkeypatch.setattr(compat.NumericArray, '__init__', capture)
    with Evtx(str(path)) as evtx:
        chunk = next(c for c in evtx.chunks() if c.offset() <= offset < c.offset() + 65536)
        record = compat.Record(chunk._buf, offset, chunk)
        assert record.record_num() == number and record.verify() and chunk.verify()
        locard = ET.fromstring(record.xml())
        actual = [n.text or '' for n in locard.findall('.//{*}Data') if n.get('Name') == field]
        assert actual == expected
        assert locard.find('.//{*}EventRecordID').text == windows.find('.//{*}EventRecordID').text
        assert locard.find('.//{*}EventID').text == windows.find('.//{*}EventID').text
        assert locard.find('.//{*}Provider').attrib == windows.find('.//{*}Provider').attrib
    assert (size, expected) in captured


def test_scalar_control_unchanged():
    with Evtx(str(Path(ROOT)/'Microsoft-Windows-WMI-Activity%4Operational.evtx')) as evtx:
        for chunk in evtx.chunks():
            for original in chunk.records():
                assert compat.Record(chunk._buf, original.offset(), chunk).xml() == original.xml()


def test_windows_empty_arrays_retain_elements():
    path = Path(ROOT)/'Microsoft-Windows-Ntfs%4Operational.evtx'
    raw = subprocess.run(['wevtutil', 'qe', str(path), '/lf:true',
                          '/q:*[System[EventRecordID=27043]]', '/c:1', '/f:xml', '/uni:true'],
                         check=True, capture_output=True, timeout=30).stdout
    windows = ET.fromstring(raw)
    with Evtx(str(path)) as evtx:
        offset = 23704896
        chunk = next(c for c in evtx.chunks() if c.offset() <= offset < c.offset()+65536)
        locard = ET.fromstring(compat.Record(chunk._buf, offset, chunk).xml())
    fields = ['HighLatencyArray', 'FailedWriteArray', 'FailedReadArray',
              'BadClusterHotfixArray', 'StatusArray', 'TableIndexArray']
    for field in fields:
        expected = [n.text or '' for n in windows.findall('.//{*}Data') if n.get('Name') == field]
        actual = [n.text or '' for n in locard.findall('.//{*}Data') if n.get('Name') == field]
        assert expected == actual == ['']


def test_supervised_control_matches_direct():
    from dataclasses import asdict
    from forensic_assistant.ingest.evtx import records
    from forensic_assistant.ingest.evtx_recovery import read_records
    path=Path(ROOT)/'Microsoft-Windows-WMI-Activity%4Operational.evtx'
    direct=[asdict(r) for r in read_records(path)]
    supervised=[asdict(r) for r in records(path)]
    assert len(direct)==1451
    assert supervised==direct
