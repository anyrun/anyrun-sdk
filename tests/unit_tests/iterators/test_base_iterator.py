"""Unit tests for anyrun.iterators.base_iterator (via concrete implementations)."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from anyrun.connectors import YaraLookupConnector
from anyrun.iterators.threat_intelligence.yara_lookup.stix_iterator import StixYaraIterator


@pytest.mark.asyncio
async def test_iterator_anext_returns_item_from_buffer():
    connector = YaraLookupConnector('mock_api_key')
    connector.get_yara_async = AsyncMock(return_value=[{'id': '1'}, {'id': '2'}])
    iterator = StixYaraIterator(connector, yara_rule='rule r {}', chunk_size=1)

    first = await iterator.__anext__()
    assert first == {'id': '1'}
    second = await iterator.__anext__()
    assert second == {'id': '2'}


@pytest.mark.asyncio
async def test_iterator_anext_raises_stop_async_iteration_when_empty():
    connector = YaraLookupConnector('mock_api_key')
    connector.get_yara_async = AsyncMock(return_value=[])
    iterator = StixYaraIterator(connector, yara_rule='rule r {}', chunk_size=1)

    with pytest.raises(StopAsyncIteration):
        await iterator.__anext__()


@pytest.mark.asyncio
async def test_iterator_read_buffer_returns_chunk_when_chunk_size_gt_one():
    connector = YaraLookupConnector('mock_api_key')
    connector.get_yara_async = AsyncMock(return_value=[{'a': 1}, {'b': 2}, {'c': 3}])
    iterator = StixYaraIterator(connector, yara_rule='rule r {}', chunk_size=2)

    first = await iterator.__anext__()
    assert first == [{'a': 1}, {'b': 2}]
    second = await iterator.__anext__()
    assert second == [{'c': 3}]


def test_iterator_sync_next_returns_items():
    connector = YaraLookupConnector('mock_api_key')
    connector.get_yara_async = AsyncMock(return_value=[{'id': '1'}, {'id': '2'}])
    iterator = StixYaraIterator(connector, yara_rule='rule r {}', chunk_size=1)
    items = list(iterator)
    assert items == [{'id': '1'}, {'id': '2'}]


def test_iterator_sync_next_raises_stop_iteration_when_empty():
    connector = YaraLookupConnector('mock_api_key')
    connector.get_yara_async = AsyncMock(return_value=[])
    iterator = StixYaraIterator(connector, yara_rule='rule r {}', chunk_size=1)
    items = list(iterator)
    assert items == []


@pytest.mark.asyncio
async def test_json_yara_iterator_read_next_chunk():
    from anyrun.iterators.threat_intelligence.yara_lookup.json_iterator import JsonYaraIterator
    connector = YaraLookupConnector('mock_api_key')
    connector.get_yara_async = AsyncMock(return_value=[{'a': 1}, {'b': 2}])
    iterator = JsonYaraIterator(connector, yara_rule='rule r {}', chunk_size=1)
    first = await iterator.__anext__()
    assert first == {'a': 1}
    second = await iterator.__anext__()
    assert second == {'b': 2}
