import pytest

from anyrun.connectors import YaraLookupConnector


@pytest.mark.asyncio
async def test_prepare_response_returns_simplified_dict_if_simplify_parameter_is_specified():
    connector = YaraLookupConnector('mock_api_key')

    response = {'someContent': 'content', 'searchInfo': {'status': 'done'}}

    assert await connector._prepare_response(response, simplify=True) == {'status': 'COMPLETED'}


@pytest.mark.asyncio
async def test_prepare_response_returns_complete_dict_if_simplify_parameter_is_not_specified():
    connector = YaraLookupConnector('mock_api_key')

    response = {'someContent': 'content', 'searchInfo': {'status': 'done'}}

    assert await connector._prepare_response(response, simplify=False) == response

@pytest.mark.asyncio
async def test_resolve_task_status_returns_valid_status_if_status_is_specified():
    connector = YaraLookupConnector('mock_api_key')

    assert await connector._resolve_task_status('new') == 'PREPARING'
    assert await connector._resolve_task_status('processing') == 'RUNNING'
    assert await connector._resolve_task_status('done') == 'COMPLETED'
    assert await connector._resolve_task_status('any_other') == 'FAILED'


@pytest.mark.asyncio
async def test_resolve_task_status_returns_none_if_status_is_not_specified():
    connector = YaraLookupConnector('mock_api_key')

    assert await connector._resolve_task_status('') is None
