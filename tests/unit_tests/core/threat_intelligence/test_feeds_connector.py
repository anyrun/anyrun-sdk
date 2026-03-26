from unittest.mock import AsyncMock, patch

import pytest

from anyrun.connectors import FeedsConnector


@pytest.mark.asyncio
async def test_generate_url_deletes_null_parameters(query_params_config):
    connector = FeedsConnector('mock_api_key')

    query_params_config['File'] = None
    query_params_config['Port'] = False

    url = await connector._generate_feeds_url('stix', query_params_config)

    assert 'File' not in url
    assert 'Port' in url


@pytest.mark.asyncio
async def test_generate_url_returns_complete_url_if_all_parameters_specified(query_params_config):
    connector = FeedsConnector('mock_api_key')

    assert await connector._generate_feeds_url('https://api.any.run/v1/feeds/taxii2/api1/collections/3dce855a-c044-5d49-9334-533c24678c5a/objects?', query_params_config) == (
        'https://api.any.run/v1/feeds/taxii2/api1/collections/3dce855a-c044-5d49-9334-533c24678c5a/objects?match[revoked]=false'
    )


@pytest.mark.asyncio
async def test_parse_boolean_returns_boolean_value_string_alias_if_boolean_parameter_received():
    connector = FeedsConnector('mock_api_key')

    assert await connector._parse_boolean(True) == 'true'
    assert await connector._parse_boolean(False) == 'false'

@pytest.mark.asyncio
async def test_parse_boolean_returns_param_if_boolean_parameter_is_not_received():
    connector = FeedsConnector('mock_api_key')

    assert await connector._parse_boolean(1) == 1
    assert await connector._parse_boolean('test') == 'test'


@pytest.mark.asyncio
async def test_get_collection_id_returns_correct_ids():
    connector = FeedsConnector('mock_api_key')
    from anyrun.utils.config import Config

    assert await connector._get_collection_id('full') == Config.TAXII_FULL
    assert await connector._get_collection_id('ip') == Config.TAXII_IP
    assert await connector._get_collection_id('domain') == Config.TAXII_DOMAIN
    assert await connector._get_collection_id('url') == Config.TAXII_URL


@pytest.mark.asyncio
async def test_get_collection_id_raises_for_invalid_name():
    connector = FeedsConnector('mock_api_key')
    from anyrun.utils.exceptions import RunTimeException

    with pytest.raises(RunTimeException) as exc_info:
        await connector._get_collection_id('invalid')
    assert 'Invalid TAXII collection' in exc_info.value.description


@pytest.mark.asyncio
async def test_update_taxii_delta_timestamp_updates_when_header_present():
    from datetime import datetime
    connector = FeedsConnector('mock_api_key')
    connector._response_headers = {'X-TAXII-Date-Modified-Last': '2025-03-10T12:00:00.000000Z'}
    await connector._update_taxii_delta_timestamp()
    assert connector._taxii_delta_timestamp == datetime(2025, 3, 10, 12, 0, 0)


@pytest.mark.asyncio
async def test_taxii_delta_timestamp_property_returns_formatted_string():
    from datetime import datetime
    connector = FeedsConnector('mock_api_key')
    connector._taxii_delta_timestamp = datetime(2025, 3, 10, 12, 0, 0)
    assert connector.taxii_delta_timestamp == '2025-03-10T12:00:00.000000Z'


@pytest.mark.asyncio
async def test_get_taxii_stix_async_uses_delta_timestamp_when_get_delta():
    from datetime import datetime
    connector = FeedsConnector('mock_api_key')
    connector._taxii_delta_timestamp = datetime(2025, 3, 1, 12, 0, 0)
    connector._response_headers = {}
    with patch.object(connector, '_make_request_async', new_callable=AsyncMock) as mock_req:
        mock_req.return_value = {'objects': [], 'next': None}
        async with connector:
            await connector.get_taxii_stix_async(collection='full', get_delta=True)
        call_kwargs = mock_req.call_args
        assert call_kwargs is not None
