"""Unit tests for anyrun.connectors.generic_environment."""

import os
from unittest.mock import AsyncMock, patch

import pytest

from anyrun.connectors.generic_environment import GenericEnvironment


def test_generic_environment_sets_and_clears_env_var():
    env = GenericEnvironment('https://custom.endpoint.example.com')
    assert 'ANYRUN_GENERIC_ENDPOINT_URL' not in os.environ

    with env:
        assert os.environ.get('ANYRUN_GENERIC_ENDPOINT_URL') == 'https://custom.endpoint.example.com'

    assert 'ANYRUN_GENERIC_ENDPOINT_URL' not in os.environ


def test_generic_environment_restores_env_after_exception():
    env = GenericEnvironment('https://custom.example.com')
    try:
        with env:
            raise ValueError('test')
    except ValueError:
        pass
    assert 'ANYRUN_GENERIC_ENDPOINT_URL' not in os.environ


@pytest.mark.asyncio
async def test_generic_request_async_returns_response():
    env = GenericEnvironment('https://custom.endpoint.example.com')
    mock_response = {'data': 'test'}
    with patch('anyrun.connectors.generic_environment.AnyRunConnector') as mock_connector_class:
        mock_connector = AsyncMock()
        mock_connector._make_request_async = AsyncMock(return_value=mock_response)
        mock_connector.__aenter__ = AsyncMock(return_value=mock_connector)
        mock_connector.__aexit__ = AsyncMock(return_value=None)
        mock_connector_class.return_value = mock_connector

        result = await env.generic_request_async('api_key', 'GET')
        assert result == mock_response


def test_generic_request_sync_returns_response():
    env = GenericEnvironment('https://custom.endpoint.example.com')
    mock_response = {'data': 'test'}
    with patch('anyrun.connectors.generic_environment.AnyRunConnector') as mock_connector_class:
        mock_connector = AsyncMock()
        mock_connector._make_request_async = AsyncMock(return_value=mock_response)
        mock_connector.__aenter__ = AsyncMock(return_value=mock_connector)
        mock_connector.__aexit__ = AsyncMock(return_value=None)
        mock_connector_class.return_value = mock_connector

        result = env.generic_request('api_key', 'GET')
        assert result == mock_response
