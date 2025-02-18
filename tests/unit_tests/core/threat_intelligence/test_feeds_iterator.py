import pytest

from anyrun.connectors.threat_intelligence import FeedsIterator, FeedsConnector
from anyrun.utils.exceptions import IteratorInitException

from tests.conftest import MockFeedsConnector


@pytest.mark.asyncio
async def test_valid_iteration(query_params_config):
    mock_connector = MockFeedsConnector()
    iterator = FeedsIterator(mock_connector, **query_params_config)

    # State before iteration
    assert iterator._pages_counter == 1
    assert len(iterator._feeds) == 0

    # The iterator gets three feeds for the first page and returns the first IOC.
    # It also increments the page counter for the next request
    assert (await iterator.__anext__()).get('id') == 'url--c955128d-e822-5121-b2dd-68a7061a13'

    # Two feeds left in the iterator
    assert len(iterator._feeds) == 2
    assert iterator._pages_counter == 2

    assert (await iterator.__anext__()).get('id') == 'url--c955128d-e822-5121-b2dd-68a7061a12'
    assert (await iterator.__anext__()).get('id') == 'url--c955128d-e822-5121-b2dd-68a7061a11'

    # Checking the valid completion of an iteration
    with pytest.raises(StopAsyncIteration):
        (await iterator.__anext__())

    assert len(iterator._feeds) == 0
    assert iterator._pages_counter == 3


@pytest.mark.asyncio
async def test_read_next_feeds_chunk_loads_data_and_increments_page_counter(query_params_config):
    mock_connector = MockFeedsConnector()
    iterator = FeedsIterator(mock_connector, **query_params_config)

    assert iterator._pages_counter == 1
    assert iterator._feeds == []

    await iterator._read_next_feeds_chunk()

    assert len(iterator._feeds) == 3
    assert iterator._pages_counter == 2


@pytest.mark.asyncio
async def test_read_next_feeds_chunk_do_nothing_if_feeds_collection_is_not_empy(query_params_config):
    mock_connector = FeedsConnector('Basic mock_api_key==')
    iterator = FeedsIterator(mock_connector, **query_params_config)

    iterator._feeds = await MockFeedsConnector()._stix_response()

    await iterator._read_next_feeds_chunk()

    # The page count has still not been changed
    assert iterator._pages_counter == 1

    # Stored feeds still haven't been changed
    assert (await iterator.__anext__()).get('id') == 'url--c955128d-e822-5121-b2dd-68a7061a13'
    assert (await iterator.__anext__()).get('id') == 'url--c955128d-e822-5121-b2dd-68a7061a12'
    assert (await iterator.__anext__()).get('id') == 'url--c955128d-e822-5121-b2dd-68a7061a11'


@pytest.mark.asyncio
async def test_valid_chunks_iteration(query_params_config):
    mock_connector = MockFeedsConnector()
    iterator = FeedsIterator(mock_connector, **query_params_config, chunk_size=3)

    next_feeds_chunk = await iterator.__anext__()

    assert isinstance(next_feeds_chunk, list)
    assert len(next_feeds_chunk) == 3

    with pytest.raises(StopAsyncIteration):
        (await iterator.__anext__())



@pytest.mark.asyncio
async def test_check_chunk_size_raises_exception_if_it_is_greater_than_specified_limit(query_params_config):
    connector = FeedsConnector('Basic mock_api_key==')

    with pytest.raises(IteratorInitException) as exception:
        FeedsIterator(connector, **query_params_config, chunk_size=101)

    assert 'The iterator chunk size can not be greater than config limit value' == str(exception.value)


@pytest.mark.asyncio
async def test_check_feed_format_raises_exception_if_it_is_not_valid(query_params_config):
    connector = FeedsConnector('Basic mock_api_key==')

    with pytest.raises(IteratorInitException) as exception:
        FeedsIterator(connector, **query_params_config, feed_format='test')

    assert 'The feed format is invalid. Expected: stix, misp, network_iocs' == str(exception.value)


@pytest.mark.asyncio
async def test_clear_query_parameters_deletes_params_according_to_feed_types_during_initialization(query_params_config):
    connector = FeedsConnector('Basic mock_api_key==')

    iterator = FeedsIterator(connector, **query_params_config, feed_format='misp')

    assert iterator._query_params.get('file') is None
    assert iterator._query_params.get('port') is None


@pytest.mark.asyncio
async def test_receive_chunk_size_returns_feed_if_chunk_size_is_equal_one(query_params_config):
    mock_connector = MockFeedsConnector()
    iterator = FeedsIterator(mock_connector, **query_params_config, chunk_size=1)

    await iterator._read_next_feeds_chunk()
    feeds = await iterator._receive_feeds_chunk()

    assert isinstance(feeds, dict)
    assert feeds.get('id') == 'url--c955128d-e822-5121-b2dd-68a7061a13'


@pytest.mark.asyncio
async def test_receive_chunk_size_returns_the_list_of_feeds_if_chunk_size_is_greater_than_one(query_params_config):
    mock_connector = MockFeedsConnector()
    iterator = FeedsIterator(mock_connector, **query_params_config, chunk_size=3)

    await iterator._read_next_feeds_chunk()
    feeds = await iterator._receive_feeds_chunk()

    assert isinstance(feeds, list)
    assert len(feeds) == 3


@pytest.mark.asyncio
async def test_receive_chunk_size_removes_feeds_from_the_buffer_upon_return(query_params_config):
    mock_connector = MockFeedsConnector()
    iterator = FeedsIterator(mock_connector, **query_params_config, chunk_size=2)

    await iterator._read_next_feeds_chunk()

    feeds = await iterator._receive_feeds_chunk()
    assert isinstance(feeds, list)
    assert len(feeds) == 2
    assert len(iterator._feeds) == 1

    feeds = await iterator._receive_feeds_chunk()
    assert isinstance(feeds, list)
    assert len(feeds) == 1
    assert len(iterator._feeds) == 0
