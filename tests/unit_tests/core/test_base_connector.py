from http import HTTPStatus

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
