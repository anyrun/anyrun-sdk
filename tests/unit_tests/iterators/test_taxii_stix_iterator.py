"""Unit tests for anyrun.iterators.threat_intelligence.feeds.taxii_stix_iterator."""

import pytest
from unittest.mock import AsyncMock

from anyrun.connectors import FeedsConnector
from anyrun.iterators.threat_intelligence.feeds.taxii_stix_iterator import TaxiiStixFeedsIterator


@pytest.mark.asyncio
async def test_taxii_stix_iterator_read_next_chunk_stops_when_no_next_page():
    connector = FeedsConnector('mock_api_key')
    connector.get_taxii_stix_async = AsyncMock(return_value={'objects': [{'id': 'obj1'}], 'next': None})
    iterator = TaxiiStixFeedsIterator(connector, chunk_size=1)

    item = await iterator.__anext__()
    assert item == {'id': 'obj1'}
    assert iterator._stop_iteration is True


@pytest.mark.asyncio
async def test_taxii_stix_iterator_read_next_chunk_continues_with_next_page():
    connector = FeedsConnector('mock_api_key')
    connector.get_taxii_stix_async = AsyncMock(
        side_effect=[
            {'objects': [{'id': 'obj1'}], 'next': 'page2'},
            {'objects': [{'id': 'obj2'}], 'next': None},
        ]
    )
    iterator = TaxiiStixFeedsIterator(connector, chunk_size=1)

    first = await iterator.__anext__()
    assert first == {'id': 'obj1'}
    second = await iterator.__anext__()
    assert second == {'id': 'obj2'}
