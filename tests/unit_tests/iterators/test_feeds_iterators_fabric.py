"""Unit tests for anyrun.iterators.threat_intelligence.feeds.feeds_iterators_fabric."""

import pytest

from anyrun.connectors import FeedsConnector
from anyrun.iterators.threat_intelligence.feeds.feeds_iterators_fabric import FeedsIterator
from anyrun.iterators.threat_intelligence.feeds.taxii_stix_iterator import TaxiiStixFeedsIterator


def test_feeds_iterator_taxii_stix_returns_taxii_stix_iterator():
    connector = FeedsConnector('mock_api_key')
    iterator = FeedsIterator.taxii_stix(connector, chunk_size=10, collection='ip')
    assert isinstance(iterator, TaxiiStixFeedsIterator)
    assert iterator._chunk_size == 10
    assert iterator._query_params['collection'] == 'ip'


def test_feeds_iterator_taxii_stix_default_params():
    connector = FeedsConnector('mock_api_key')
    iterator = FeedsIterator.taxii_stix(connector)
    assert iterator._query_params['collection'] == 'full'
    assert iterator._query_params['match_type'] == 'indicator'
    assert iterator._chunk_size == 1
