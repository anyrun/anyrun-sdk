"""Unit tests for anyrun.iterators.threat_intelligence.yara_lookup.yara_lookup_iterators_fabric."""

import pytest

from anyrun.connectors import YaraLookupConnector
from anyrun.iterators.threat_intelligence.yara_lookup.yara_lookup_iterators_fabric import YaraIterator
from anyrun.iterators.threat_intelligence.yara_lookup.stix_iterator import StixYaraIterator
from anyrun.iterators.threat_intelligence.yara_lookup.json_iterator import JsonYaraIterator


def test_yara_iterator_stix_returns_stix_yara_iterator():
    connector = YaraLookupConnector('mock_api_key')
    iterator = YaraIterator.stix(connector, yara_rule='rule test {}', chunk_size=5)
    assert isinstance(iterator, StixYaraIterator)
    assert iterator._yara_rule == 'rule test {}'
    assert iterator._chunk_size == 5


def test_yara_iterator_json_returns_json_yara_iterator():
    connector = YaraLookupConnector('mock_api_key')
    iterator = YaraIterator.json(connector, yara_rule='rule test {}')
    assert isinstance(iterator, JsonYaraIterator)
    assert iterator._yara_rule == 'rule test {}'
    assert iterator._chunk_size == 1
