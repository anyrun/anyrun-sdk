from http import HTTPStatus
from unittest.mock import AsyncMock, patch

import pytest
import aiohttp

from anyrun.connectors.base_connector import AnyRunConnector
from anyrun.utils.exceptions import RunTimeException


@pytest.mark.asyncio
async def test_check_make_request_async_raises_exception_if_connector_is_executed_outside_the_context_manager():
    base_connector = AnyRunConnector('mock_api_key')

    with pytest.raises(RunTimeException) as exception:
        await base_connector._make_request_async('GET', 'https://any.run')

    assert exception.value.description == 'The connector object must be executed using the context manager'


@pytest.mark.asyncio
async def test_setup_connector_if_verify_ssl_option_is_specified():
    base_connector = AnyRunConnector('mock_api_key', verify_ssl=True)

    assert isinstance(base_connector._connector, aiohttp.BaseConnector)


@pytest.mark.asyncio
async def test_open_session_creates_new_session_if_active_session_is_not_exists():
    base_connector = AnyRunConnector('mock_api_key')

    assert base_connector._session is None

    await base_connector._open_session()

    assert isinstance(base_connector._session, aiohttp.ClientSession)


@pytest.mark.asyncio
async def test_open_session_not_creates_new_session_if_active_session_is_exists():
    base_connector = AnyRunConnector('mock_api_key')

    await base_connector._open_session()
    session_id = id(base_connector._session)

    await base_connector._open_session()
    assert session_id == id(base_connector._session)


@pytest.mark.asyncio
async def test_close_session_set_session_parameter_value_to_none():
    base_connector = AnyRunConnector('mock_api_key')

    await base_connector._open_session()
    assert isinstance(base_connector._session, aiohttp.ClientSession)

    await base_connector._close_session()
    assert base_connector._session is None


@pytest.mark.asyncio
async def test_check_response_status_raises_exception_if_code_200_is_not_received():
    base_connector = AnyRunConnector('mock_api_key')

    error_response = {
        'code': HTTPStatus.UNAUTHORIZED,
        'message': 'Authentication required to access this resource'
    }

    with pytest.raises(RunTimeException) as exception:
        await base_connector._check_response_status(error_response, HTTPStatus.UNAUTHORIZED)

    assert exception.value.description == 'Authentication required to access this resource'


@pytest.mark.asyncio
async def test_check_response_status_returns_response_data_if_code_200_is_received():
    base_connector = AnyRunConnector('mock_api_key')

    response_data = 'some_data'
    response = await base_connector._check_response_status(response_data, HTTPStatus.OK)

    assert response == response_data


@pytest.mark.asyncio
async def test_api_key_validator_raises_exception_if_api_key_is_not_a_string():
    with pytest.raises(RunTimeException) as exception:
        AnyRunConnector(123)

    assert exception.value.description == 'The ANY.RUN API key must be a valid string'


@pytest.mark.asyncio
async def test_api_key_validator_raises_exception_if_api_key_is_empty():
    with pytest.raises(RunTimeException) as exception:
        AnyRunConnector('')

    assert exception.value.description == 'The ANY.RUN API key can not be empty.'


def test_generate_proxy_config_without_auth():
    base_connector = AnyRunConnector('mock_api_key')
    base_connector._proxy = 'https://proxy.example.com:8080'
    base_connector._proxy_username = None
    base_connector._proxy_password = None
    config = base_connector._generate_proxy_config()
    assert config == {'https': 'https://proxy.example.com:8080'}


def test_generate_proxy_config_with_auth():
    base_connector = AnyRunConnector('mock_api_key')
    base_connector._proxy = 'https://proxy.example.com:8080'
    base_connector._proxy_username = 'user'
    base_connector._proxy_password = 'pass'
    config = base_connector._generate_proxy_config()
    assert 'https' in config
    assert 'user' in config['https']
    assert 'pass' in config['https']


def test_generate_proxy_config_returns_none_when_no_proxy():
    base_connector = AnyRunConnector('mock_api_key')
    base_connector._proxy = None
    assert base_connector._generate_proxy_config() is None


@pytest.mark.asyncio
async def test_check_response_status_uses_description_key_when_message_missing():
    base_connector = AnyRunConnector('mock_api_key')
    error_response = {'description': 'Error from description field', 'code': 400}
    with pytest.raises(RunTimeException) as exc_info:
        await base_connector._check_response_status(error_response, 400)
    assert exc_info.value.description == 'Error from description field'


def test_sync_context_manager_opens_and_closes_session():
    base_connector = AnyRunConnector('mock_api_key')
    with base_connector:
        assert base_connector._session is not None
    assert base_connector._session is None


@pytest.mark.asyncio
async def test_async_context_manager_opens_and_closes_session():
    base_connector = AnyRunConnector('mock_api_key')
    async with base_connector:
        assert base_connector._session is not None
    assert base_connector._session is None


@pytest.mark.asyncio
async def test_check_proxy_async_returns_ok_when_request_succeeds():
    base_connector = AnyRunConnector('mock_api_key')
    with patch.object(base_connector, '_make_request_async', new_callable=AsyncMock, return_value=None):
        async with base_connector:
            result = await base_connector.check_proxy_async()
    assert result == {'status': 'ok', 'description': 'Successful proxy verification'}


def test_check_proxy_sync_returns_ok():
    base_connector = AnyRunConnector('mock_api_key')
    with patch.object(base_connector, '_make_request_async', new_callable=AsyncMock, return_value=None):
        with base_connector:
            result = base_connector.check_proxy()
    assert result['status'] == 'ok'
