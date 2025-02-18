import pytest

from anyrun.connectors.base_connector import AnyRunConnector


@pytest.mark.asyncio
async def test_check_response_status_returns_json_with_the_error_explanation_if_code_200_is_not_received():
    base_connector = AnyRunConnector('Basic mock_api_key==')

    error_response = {
        'code': 401,
        'message': 'Authentication required to access this resource'
    }

    error_explanation_json = {
            'status': 'error',
            'code': 401,
            'description': 'Authentication required to access this resource'
        }

    assert await base_connector._check_response_status(error_response, 401) == error_explanation_json
