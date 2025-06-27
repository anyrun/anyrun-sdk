import pytest

from anyrun.connectors import FeedsConnector


@pytest.mark.asyncio
async def test_generate_url_returns_deletes_empty_parameters(query_params_config):
    connector = FeedsConnector('mock_api_key')

    query_params_config['File'] = None
    query_params_config['Port'] = False

    url = await connector._generate_feeds_url('stix', query_params_config)

    assert 'File' not in url
    assert 'Port' not in url


@pytest.mark.asyncio
async def test_generate_url_returns_complete_url_if_all_parameters_specified(query_params_config):
    connector = FeedsConnector('mock_api_key')

    url = await connector._generate_feeds_url('https://api.any.run/v1/feeds/misp.json?', query_params_config)
    for param, value in query_params_config.items():
        if value:
            assert param in url
            assert str(value) in url

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
