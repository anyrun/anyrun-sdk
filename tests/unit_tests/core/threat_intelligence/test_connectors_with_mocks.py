"""Unit tests for threat intelligence connectors with mocked HTTP."""

from unittest.mock import AsyncMock, patch

import pytest

from anyrun.connectors import FeedsConnector, LookupConnector, YaraLookupConnector


@pytest.mark.asyncio
async def test_feeds_connector_get_taxii_stix_async():
    connector = FeedsConnector('mock_api_key')
    mock_objects = [{'type': 'indicator', 'id': '1'}]
    with patch.object(connector, '_make_request_async', new_callable=AsyncMock) as mock_req:
        mock_req.return_value = {'objects': mock_objects, 'next': None}
        connector._response_headers = {}
        async with connector:
            result = await connector.get_taxii_stix_async(collection='full')
        assert result['objects'] == mock_objects


@pytest.mark.asyncio
async def test_feeds_connector_check_authorization_async():
    connector = FeedsConnector('mock_api_key')
    with patch.object(connector, '_make_request_async', new_callable=AsyncMock):
        async with connector:
            result = await connector.check_authorization_async()
        assert result['status'] == 'ok'


def test_feeds_connector_check_authorization_sync():
    connector = FeedsConnector('mock_api_key')
    with patch.object(connector, 'check_authorization_async', new_callable=AsyncMock,
                      return_value={'status': 'ok', 'description': 'ok'}):
        result = connector.check_authorization()
        assert result['status'] == 'ok'


@pytest.mark.asyncio
async def test_lookup_connector_check_authorization_async():
    connector = LookupConnector('mock_api_key')
    with patch.object(connector, '_make_request_async', new_callable=AsyncMock):
        async with connector:
            result = await connector.check_authorization_async()
        assert result['status'] == 'ok'


def test_lookup_connector_check_authorization_sync():
    connector = LookupConnector('mock_api_key')
    with patch.object(connector, 'check_authorization_async', new_callable=AsyncMock,
                      return_value={'status': 'ok', 'description': 'ok'}):
        result = connector.check_authorization()
        assert result['status'] == 'ok'


@pytest.mark.asyncio
async def test_lookup_connector_get_intelligence_async_returns_dict():
    connector = LookupConnector('mock_api_key')
    mock_response = {'summary': {}, 'destinationPort': [], 'destinationIPgeo': [], 'destinationIpAsn': [],
                     'relatedFiles': [], 'industries': [], 'destinationIP': [], 'relatedDNS': [],
                     'relatedURLs': [], 'sourceTasks': []}
    with patch.object(connector, '_make_request_async', new_callable=AsyncMock, return_value=mock_response):
        async with connector:
            result = await connector.get_intelligence_async(parse_response=False)
        assert result == mock_response


@pytest.mark.asyncio
async def test_yara_lookup_connector_check_authorization_async():
    connector = YaraLookupConnector('mock_api_key')
    with patch.object(connector, '_make_request_async', new_callable=AsyncMock):
        async with connector:
            result = await connector.check_authorization_async()
        assert result['status'] == 'ok'


@pytest.mark.asyncio
async def test_yara_lookup_connector_run_yara_search_async():
    connector = YaraLookupConnector('mock_api_key')
    with patch.object(connector, '_make_request_async', new_callable=AsyncMock, return_value={'queryId': 'search-123'}):
        async with connector:
            result = await connector.run_yara_search_async('rule Test {}')
        assert result == 'search-123'


@pytest.mark.asyncio
async def test_yara_lookup_connector_get_search_result_async():
    connector = YaraLookupConnector('mock_api_key')
    with patch.object(connector, '_make_request_async', new_callable=AsyncMock, return_value={'matches': [{'id': '1'}]}):
        async with connector:
            result = await connector.get_search_result_async('search-123')
        assert result == [{'id': '1'}]


@pytest.mark.asyncio
async def test_yara_lookup_connector_get_search_result_async_simplify_empty_returns_none():
    connector = YaraLookupConnector('mock_api_key')
    with patch.object(connector, '_make_request_async', new_callable=AsyncMock, return_value={'matches': []}):
        async with connector:
            result = await connector.get_search_result_async('search-123', simplify=True)
        assert result is None


@pytest.mark.asyncio
async def test_yara_lookup_connector_get_stix_search_result_async():
    connector = YaraLookupConnector('mock_api_key')
    with patch.object(connector, '_make_request_async', new_callable=AsyncMock,
                      return_value={'data': {'objects': [{'id': '1'}]}}):
        async with connector:
            result = await connector.get_stix_search_result_async('search-123')
        assert result == [{'id': '1'}]


@pytest.mark.asyncio
async def test_yara_lookup_connector_get_search_status_async():
    connector = YaraLookupConnector('mock_api_key')
    with patch.object(connector, '_make_request_async', new_callable=AsyncMock,
                      return_value={'searchInfo': {'status': 'done'}}):
        async with connector:
            statuses = []
            async for s in connector.get_search_status_async('search-123'):
                statuses.append(s)
        assert len(statuses) >= 1
        assert statuses[-1].get('status') == 'COMPLETED'


@pytest.mark.asyncio
async def test_lookup_connector_get_intelligence_async_with_lookup_depth():
    connector = LookupConnector('mock_api_key')
    mock_response = {
        'summary': {}, 'destinationPort': [], 'destinationIPgeo': [], 'destinationIpAsn': [],
        'relatedFiles': [], 'industries': [], 'destinationIP': [], 'relatedDNS': [],
        'relatedURLs': [], 'sourceTasks': []
    }
    with patch.object(connector, '_make_request_async', new_callable=AsyncMock, return_value=mock_response):
        async with connector:
            result = await connector.get_intelligence_async(lookup_depth=30, parse_response=False)
        assert result == mock_response


@pytest.mark.asyncio
async def test_lookup_connector_get_intelligence_async_parse_response_true():
    from anyrun.models.lookup_summary import LookupSummary
    connector = LookupConnector('mock_api_key')
    mock_response = {
        'summary': {'threatLevel': None, 'lastSeen': None, 'tags': None},
        'destinationPort': [], 'destinationIPgeo': [], 'destinationIpAsn': [],
        'relatedFiles': [], 'industries': [], 'destinationIP': [], 'relatedDNS': [],
        'relatedURLs': [], 'sourceTasks': []
    }
    with patch.object(connector, '_make_request_async', new_callable=AsyncMock, return_value=mock_response):
        async with connector:
            result = await connector.get_intelligence_async(parse_response=True)
        assert isinstance(result, LookupSummary)


@pytest.mark.asyncio
async def test_yara_lookup_connector_get_yara_async():
    connector = YaraLookupConnector('mock_api_key')
    with patch.object(connector, 'run_yara_search_async', new_callable=AsyncMock, return_value='search-1'), \
         patch.object(connector, 'get_search_status_async') as mock_status, \
         patch.object(connector, 'get_stix_search_result_async', new_callable=AsyncMock, return_value=[{'m': 1}]):
        async def status_gen():
            yield {'status': 'COMPLETED'}
        mock_status.return_value = status_gen()
        async with connector:
            result = await connector.get_yara_async('rule r {}', stix=False)
        assert result == [{'m': 1}]


@pytest.mark.asyncio
async def test_yara_lookup_connector_get_yara_async_stix():
    connector = YaraLookupConnector('mock_api_key')
    with patch.object(connector, 'run_yara_search_async', new_callable=AsyncMock, return_value='search-1'), \
         patch.object(connector, 'get_search_status_async') as mock_status, \
         patch.object(connector, 'get_search_result_async', new_callable=AsyncMock, return_value=[{'id': '1'}]):
        async def status_gen():
            yield {'status': 'COMPLETED'}
        mock_status.return_value = status_gen()
        async with connector:
            result = await connector.get_yara_async('rule r {}', stix=True)
        assert result == [{'id': '1'}]
