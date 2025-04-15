from http import HTTPStatus

import pytest

from anyrun.utils.exceptions import RunTimeException
from anyrun.connectors.base_connector import AnyRunConnector


@pytest.mark.asyncio
async def test_exception_interface_works_correctly():
    base_connector = AnyRunConnector('mock_api_key')

    error_response = {
        'code': HTTPStatus.UNAUTHORIZED,
        'message': 'Authentication required to access this resource'
    }

    with pytest.raises(RunTimeException) as exception:
        await base_connector._check_response_status(error_response, HTTPStatus.UNAUTHORIZED)

    assert exception.value.description == 'Authentication required to access this resource'
    assert exception.value.status_code == HTTPStatus.UNAUTHORIZED
    assert exception.value.json == {
        'description': 'Authentication required to access this resource',
        'code': HTTPStatus.UNAUTHORIZED
    }
