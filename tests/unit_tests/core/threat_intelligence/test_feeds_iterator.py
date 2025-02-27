import pytest

from anyrun.iterators import FeedsIterator

from tests.conftest import MockFeedsConnector


@pytest.mark.asyncio
async def test_valid_iteration(query_params_config):
    mock_connector = MockFeedsConnector()
    iterator = FeedsIterator.stix(mock_connector, **query_params_config)

    # State before iteration
    assert iterator._pages_counter == 1
    assert len(iterator._buffer) == 0

    # The iterator gets three feeds for the first page and returns the first IOC.
    # It also increments the page counter for the next request
    assert (await iterator.__anext__()).get('id') == 'url--c955128d-e822-5121-b2dd-68a7061a13'

    # Two feeds left in the iterator
    assert len(iterator._buffer) == 2
    assert iterator._pages_counter == 2

    assert (await iterator.__anext__()).get('id') == 'url--c955128d-e822-5121-b2dd-68a7061a12'
    assert (await iterator.__anext__()).get('id') == 'url--c955128d-e822-5121-b2dd-68a7061a11'

    # Checking the valid completion of an iteration
    with pytest.raises(StopAsyncIteration):
        (await iterator.__anext__())

    assert len(iterator._buffer) == 0
    assert iterator._pages_counter == 3


@pytest.mark.asyncio
async def test_read_next_feeds_chunk_loads_data_and_increments_page_counter(query_params_config):
    mock_connector = MockFeedsConnector()
    iterator = FeedsIterator.stix(mock_connector, **query_params_config)

    assert iterator._pages_counter == 1
    assert iterator._buffer == []

    await iterator._read_next_chunk()

    assert len(iterator._buffer) == 3
    assert iterator._pages_counter == 2


@pytest.mark.asyncio
async def test_valid_chunks_iteration(query_params_config):
    mock_connector = MockFeedsConnector()
    iterator = FeedsIterator.stix(mock_connector, **query_params_config, chunk_size=3)

    next_feeds_chunk = await iterator.__anext__()

    assert isinstance(next_feeds_chunk, list)
    assert len(next_feeds_chunk) == 3

    with pytest.raises(StopAsyncIteration):
        (await iterator.__anext__())


@pytest.mark.asyncio
async def test_read_buffer_returns_feed_if_chunk_size_is_equal_one(query_params_config):
    mock_connector = MockFeedsConnector()
    iterator = FeedsIterator.stix(mock_connector, **query_params_config, chunk_size=1)

    await iterator._read_next_chunk()
    feeds = await iterator._read_buffer()

    assert isinstance(feeds, dict)
    assert feeds.get('id') == 'url--c955128d-e822-5121-b2dd-68a7061a13'


@pytest.mark.asyncio
async def test_read_buffer_returns_the_list_of_feeds_if_chunk_size_is_greater_than_one(query_params_config):
    mock_connector = MockFeedsConnector()
    iterator = FeedsIterator.stix(mock_connector, **query_params_config, chunk_size=3)

    await iterator._read_next_chunk()
    feeds = await iterator._read_buffer()

    assert isinstance(feeds, list)
    assert len(feeds) == 3


@pytest.mark.asyncio
async def test_read_buffer_removes_feeds_from_the_buffer_upon_return(query_params_config):
    mock_connector = MockFeedsConnector()
    iterator = FeedsIterator.stix(mock_connector, **query_params_config, chunk_size=2)

    await iterator._read_next_chunk()

    feeds = await iterator._read_buffer()
    assert isinstance(feeds, list)
    assert len(feeds) == 2
    assert len(iterator._buffer) == 1

    feeds = await iterator._read_buffer()
    assert isinstance(feeds, list)
    assert len(feeds) == 1
    assert len(iterator._buffer) == 0
