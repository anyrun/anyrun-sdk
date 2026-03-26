"""Unit tests for anyrun.models.lookup_summary."""

from datetime import datetime

import pytest

from anyrun.models.lookup_summary import (
    FileHashes,
    FileMetaData,
    DestinationIpAsn,
    Industry,
    RelatedFile,
    RelatedDNS,
    RelatedURL,
    RelatedIP,
    SourceTask,
    Summary,
    LookupSummary,
)


def test_file_hashes_model():
    h = FileHashes(md5='m', sha1='s1', sha256='s256', ssdeep='ss')
    assert h.md5 == 'm'
    assert h.sha256 == 's256'


def test_summary_model():
    s = Summary(threatLevel=1, lastSeen=datetime(2025, 1, 1), tags=['tag1'])
    assert s.threatLevel == 1
    assert s.tags == ['tag1']


def _empty_summary():
    return Summary(threatLevel=None, lastSeen=None, tags=None)


def test_lookup_summary_is_empty_true():
    """When all list fields are empty, is_empty returns True."""
    data = {
        'summary': _empty_summary(),
        'destinationPort': [],
        'destinationIPgeo': [],
        'destinationIpAsn': [],
        'relatedFiles': [],
        'industries': [],
        'destinationIP': [],
        'relatedDNS': [],
        'relatedURLs': [],
        'sourceTasks': [],
    }
    obj = LookupSummary(**data)
    assert obj.is_empty() is True


def test_lookup_summary_is_empty_false():
    """When any list field has data, is_empty returns False."""
    data = {
        'summary': _empty_summary(),
        'destinationPort': [443],
        'destinationIPgeo': [],
        'destinationIpAsn': [],
        'relatedFiles': [],
        'industries': [],
        'destinationIP': [],
        'relatedDNS': [],
        'relatedURLs': [],
        'sourceTasks': [],
    }
    obj = LookupSummary(**data)
    assert obj.is_empty() is False


def test_lookup_summary_verdict():
    data = {
        'summary': Summary(threatLevel=0, lastSeen=None, tags=None),
        'destinationPort': [],
        'destinationIPgeo': [],
        'destinationIpAsn': [],
        'relatedFiles': [],
        'industries': [],
        'destinationIP': [],
        'relatedDNS': [],
        'relatedURLs': [],
        'sourceTasks': [],
    }
    obj = LookupSummary(**data)
    assert obj.verdict() == 'No info'

    obj.summary.threatLevel = 1
    assert obj.verdict() == 'Suspicious'

    obj.summary.threatLevel = 2
    assert obj.verdict() == 'Malicious'

    obj.summary.threatLevel = None
    assert obj.verdict() is None


def test_lookup_summary_last_modified():
    dt = datetime(2025, 3, 10, 12, 30, 0)
    data = {
        'summary': Summary(threatLevel=None, lastSeen=dt, tags=None),
        'destinationPort': [],
        'destinationIPgeo': [],
        'destinationIpAsn': [],
        'relatedFiles': [],
        'industries': [],
        'destinationIP': [],
        'relatedDNS': [],
        'relatedURLs': [],
        'sourceTasks': [],
    }
    obj = LookupSummary(**data)
    assert obj.last_modified() == '2025-03-10 12:30:00'

    obj.summary.lastSeen = None
    assert obj.last_modified() is None


def test_lookup_summary_tasks():
    data = {
        'summary': _empty_summary(),
        'destinationPort': [],
        'destinationIPgeo': [],
        'destinationIpAsn': [],
        'relatedFiles': [],
        'industries': [],
        'destinationIP': [],
        'relatedDNS': [],
        'relatedURLs': [],
        'sourceTasks': [
            SourceTask(related='task1'),
            SourceTask(related='task2'),
            SourceTask(related='task3'),
        ],
    }
    obj = LookupSummary(**data)
    assert obj.tasks() == ['task1', 'task2', 'task3']
    assert obj.tasks(tasks_range=2) == ['task1', 'task2']

    data['sourceTasks'] = []
    obj = LookupSummary(**data)
    assert obj.tasks() is None


def test_lookup_summary_tags():
    data = {
        'summary': Summary(threatLevel=None, lastSeen=None, tags=['a', 'b']),
        'destinationPort': [],
        'destinationIPgeo': [],
        'destinationIpAsn': [],
        'relatedFiles': [],
        'industries': [],
        'destinationIP': [],
        'relatedDNS': [],
        'relatedURLs': [],
        'sourceTasks': [],
    }
    obj = LookupSummary(**data)
    assert obj.tags() == 'a, b'

    obj.summary.tags = None
    assert obj.tags() is None


def test_lookup_summary_industries():
    data = {
        'summary': _empty_summary(),
        'destinationPort': [],
        'destinationIPgeo': [],
        'destinationIpAsn': [],
        'relatedFiles': [],
        'industries': [
            Industry(industryName='Tech', confidence=80),
            Industry(industryName='Finance', confidence=90),
        ],
        'destinationIP': [],
        'relatedDNS': [],
        'relatedURLs': [],
        'sourceTasks': [],
    }
    obj = LookupSummary(**data)
    # Sorted by confidence desc: Finance(90%), Tech(80%)
    assert obj.industries() == 'Finance(90%), Tech(80%)'

    data['industries'] = []
    obj = LookupSummary(**data)
    assert obj.industries() is None


def test_lookup_summary_country():
    data = {
        'summary': _empty_summary(),
        'destinationPort': [],
        'destinationIPgeo': ['US'],
        'destinationIpAsn': [],
        'relatedFiles': [],
        'industries': [],
        'destinationIP': [],
        'relatedDNS': [],
        'relatedURLs': [],
        'sourceTasks': [],
    }
    obj = LookupSummary(**data)
    assert obj.country() == 'US'

    data['destinationIPgeo'] = []
    obj = LookupSummary(**data)
    assert obj.country() is None


def test_lookup_summary_port():
    data = {
        'summary': _empty_summary(),
        'destinationPort': [443],
        'destinationIPgeo': [],
        'destinationIpAsn': [],
        'relatedFiles': [],
        'industries': [],
        'destinationIP': [],
        'relatedDNS': [],
        'relatedURLs': [],
        'sourceTasks': [],
    }
    obj = LookupSummary(**data)
    assert obj.port() == 443


def test_lookup_summary_asn():
    data = {
        'summary': _empty_summary(),
        'destinationPort': [],
        'destinationIPgeo': [],
        'destinationIpAsn': [DestinationIpAsn(asn='AS12345', date=datetime(2025, 1, 1))],
        'relatedFiles': [],
        'industries': [],
        'destinationIP': [],
        'relatedDNS': [],
        'relatedURLs': [],
        'sourceTasks': [],
    }
    obj = LookupSummary(**data)
    assert obj.asn() == 'AS12345'


def test_lookup_summary_file_meta():
    hashes = FileHashes(md5='m', sha1='s1', sha256='s256', ssdeep='ss')
    rf = RelatedFile(fileName='C:\\path\\file.exe', fileExtension='exe', hashes=hashes)
    data = {
        'summary': _empty_summary(),
        'destinationPort': [],
        'destinationIPgeo': [],
        'destinationIpAsn': [],
        'relatedFiles': [rf],
        'industries': [],
        'destinationIP': [],
        'relatedDNS': [],
        'relatedURLs': [],
        'sourceTasks': [],
    }
    obj = LookupSummary(**data)
    meta = obj.file_meta()
    assert meta is not None
    assert meta.filename == 'file.exe'
    assert meta.filepath == 'C:\\path\\file.exe'
    assert meta.file_extension == 'exe'
    assert meta.hashes.sha256 == 's256'

    data['relatedFiles'] = []
    obj = LookupSummary(**data)
    assert obj.file_meta() is None


def test_lookup_summary_intelligence_url():
    url = LookupSummary.intelligence_url('test.hash')
    assert 'https://intelligence.any.run/' in url
    assert 'test.hash' in url
