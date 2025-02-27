import pytest

from anyrun.connectors.threat_intelligence.lookup_connector import LookupConnector


@pytest.mark.asyncio
async def test_add_time_ranges_returns_request_body_with_time_ranges_if_at_least_one_specified():
    connector = LookupConnector('mock_api_key')

    assert 'startDate' in await connector._add_time_ranges({}, '2025-01-01', None)
    assert 'endDate' in await connector._add_time_ranges({}, None, '2025-01-01')

    request_body = await connector._add_time_ranges({}, '2025-01-01', '2025-01-02')
    assert 'startDate' in request_body and 'endDate' in request_body


@pytest.mark.asyncio
async def test_add_time_ranges_returns_request_body_without_time_ranges_if_none_specified():
    connector = LookupConnector('mock_api_key')

    request_body = await connector._add_time_ranges({}, None, None)
    assert 'startDate' not in request_body and 'endDate' not in request_body


@pytest.mark.asyncio
async def test_generate_query_returns_valid_query():
    connector = LookupConnector('mock_api_key')

    query = await connector._generate_query({'URL': 'https://any.run', 'osBitVersion': '64'})
    assert 'URL:"https://any.run" AND osBitVersion:"64"' == query


@pytest.mark.asyncio
async def test_generate_query_returns_query_without_none_parameters():
    connector = LookupConnector('mock_api_key')

    query = await connector._generate_query({'startDate': '2025-01-01', 'osBitVersion': '64', 'domainName': None})
    assert 'domainName' not in query


@pytest.mark.asyncio
async def test_generate_request_body_returns_a_valid_body():
    connector = LookupConnector('mock_api_key')

    request_body = await connector._generate_request_body(
        '2025-01-01',
        '2025-01-02',
        None,
        {'URL': 'https://any.run', 'osBitVersion': '64'}
    )
    assert len(request_body) == 3
    assert request_body.get('query') == 'URL:"https://any.run" AND osBitVersion:"64"'
    assert request_body.get('startDate') == '2025-01-01'
    assert request_body.get('endDate') == '2025-01-02'


@pytest.mark.asyncio
async def test_generate_request_body_has_a_higher_priority_to_the_raw_query():
    connector = LookupConnector('mock_api_key')

    request_body = await connector._generate_request_body(
        None,
        None,
        'startDate:"2025-01-01" AND osBitVersion:"64"',
        {'URL': 'https://any.run', 'threatLevel': 'info'}
    )

    assert request_body.get('query') == 'startDate:"2025-01-01" AND osBitVersion:"64"'
