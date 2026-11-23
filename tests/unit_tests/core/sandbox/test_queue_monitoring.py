"""
Tests for monitoring queued tasks and for removing a task from the queue.

Event payloads below are copies of real API responses. The server keeps one event stream open while a task goes
from the queue to the running state and then to completion, and it answers an unknown or removed id with a 404 JSON
response instead of a stream.
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from anyrun.connectors import SandboxConnector
from anyrun.utils.exceptions import RunTimeException

QUEUE_ID = '98115696-868d-4abd-bd3e-033a2e327aeb'
REAL_UUID = '3d68f8af-a720-4785-96d6-e44e20b0b2c5'
QUEUED = b'data: {"error": false, "message": "Task is queued and awaits execution."}'
LAUNCHED_SOON = b'data: {"error": false, "message": "Task will be launched soon."}'
CANCELED = b'data: {"error": false, "message": "Task status is unknown or the task was canceled"}'
PRE_LAUNCH_ERROR = b'data: {"error": true, "message": "Pre-launch error occurred."}'

# Real answer of GET /v1/analysis/queue with two waiting tasks (ids shortened to the first one)
ENVIRONMENT = {
    'os': 'Windows', 'bitness': 64, 'version': '10', 'variant': 'Professional', 'locale': 'en-US', 'type': 'complete',
    'presentation': False, '_id': '6afe93c80bd04a026b5e13c1',
}
QUEUE_LIST_RESPONSE = {
    'error': False,
    'data': [
        {
            'queueTaskId': 'ab395655-97c1-4333-9adb-34391958ea66', 'tasksAhead': 0, 'queueLastReason': 'user-parallels-limit',
            'environments': ENVIRONMENT, 'createdAt': '2026-11-19T06:14:32.529Z',
        },
        {
            'queueTaskId': 'a6aba202-53f9-4fc7-a205-e3d9192af646', 'tasksAhead': 1, 'queueLastReason': 'user-parallels-limit',
            'environments': ENVIRONMENT, 'createdAt': '2026-11-19T06:14:36.280Z',
        },
    ],
}


def running(status: int, remaining: int = 59, completed: bool = False) -> bytes:
    completed = 'true' if completed else 'false'
    return (
        f'data: {{"task": {{"status": {status}, "remaining": {remaining}, "uuid": "{REAL_UUID}"}}, '
        f'"completed": {completed}, "error": false}}'
    ).encode()


def stream_response(*lines: bytes) -> MagicMock:
    """Builds an aiohttp response with an event stream; every line is followed by an empty one, like the real stream"""
    chunks = []
    for line in lines:
        chunks += [line + b'\n', b'\n']

    response = MagicMock()
    response.content.readuntil = AsyncMock(side_effect=[*chunks, b''])
    response.content_type = 'text/event-stream'
    return response


def connector_with_stream(*lines: bytes):
    connector = SandboxConnector.windows('key')
    connector._make_request_async = AsyncMock(return_value=stream_response(*lines))
    return connector


# ---------- event classification ----------


@pytest.mark.parametrize('chunk', [QUEUED, LAUNCHED_SOON])
async def test_queued_event_is_prepared_as_queued_status(chunk):
    connector = SandboxConnector.windows('key')

    response = await connector._prepare_response(chunk, True, QUEUE_ID)

    assert response['status'] == 'QUEUED'
    assert response['seconds_remaining'] is None
    assert response['task_uuid'] is None
    assert response['info'].startswith('Task ')


@pytest.mark.parametrize(
    ('chunk', 'status'),
    [
        (CANCELED, 'CANCELED'),
        (PRE_LAUNCH_ERROR, 'FAILED'),
        (b'data: {"error": false, "message": "Something the SDK has not seen"}', 'UNKNOWN'),
        (b'data: {}', 'UNKNOWN'),
    ],
)
async def test_other_events_without_task_data_are_prepared_without_exceptions(chunk, status):
    connector = SandboxConnector.windows('key')

    response = await connector._prepare_response(chunk, True, QUEUE_ID)

    assert response['status'] == status
    assert response['task_uuid'] is None


async def test_running_event_exposes_the_real_task_uuid_and_links_to_it():
    connector = SandboxConnector.windows('key')

    response = await connector._prepare_response(running(50, 59), True, QUEUE_ID)

    assert response == {
        'status': 'RUNNING',
        'seconds_remaining': 59,
        'task_uuid': REAL_UUID,
        'info': f'For interactive analysis follow: https://app.any.run/tasks/{REAL_UUID}',
    }


@pytest.mark.parametrize(('code', 'status'), [(24, 'PREPARING'), (45, 'PREPARING'), (55, 'RUNNING'), (100, 'COMPLETED'), (-1, 'FAILED')])
async def test_task_status_codes_are_resolved(code, status):
    connector = SandboxConnector.windows('key')

    assert (await connector._prepare_response(running(code), True, QUEUE_ID))['status'] == status


@pytest.mark.parametrize('chunk', [QUEUED, LAUNCHED_SOON, CANCELED, PRE_LAUNCH_ERROR, running(50)])
async def test_events_are_returned_unchanged_if_simplify_is_not_specified(chunk):
    connector = SandboxConnector.windows('key')

    response = await connector._prepare_response(chunk, False, QUEUE_ID)

    assert response == json.loads(chunk[6:])


# ---------- the whole stream ----------


async def test_stream_goes_from_queued_to_running_to_completed_on_one_connection():
    connector = connector_with_stream(QUEUED, QUEUED, running(50, 59), running(55, 0), running(100, 0, completed=True))

    statuses = [status async for status in connector.get_task_status_async(QUEUE_ID)]

    assert [status['status'] for status in statuses] == ['QUEUED', 'QUEUED', 'RUNNING', 'RUNNING', 'COMPLETED']
    assert [status['task_uuid'] for status in statuses] == [None, None, REAL_UUID, REAL_UUID, REAL_UUID]
    assert connector._make_request_async.await_count == 1


async def test_stream_of_a_task_that_waits_with_the_launched_soon_message():
    connector = connector_with_stream(LAUNCHED_SOON, QUEUED, running(50))

    statuses = [status async for status in connector.get_task_status_async(QUEUE_ID)]

    assert [status['status'] for status in statuses] == ['QUEUED', 'QUEUED', 'RUNNING']


async def test_unknown_or_removed_id_raises_the_server_message_with_aiohttp():
    connector = SandboxConnector.windows('key')
    response = AsyncMock(status=404, content_type='application/json')
    response.json = AsyncMock(return_value={'error': True, 'message': 'Task not found'})
    connector._make_request_async = AsyncMock(return_value=response)

    with pytest.raises(RunTimeException, match='Task not found') as error:
        [status async for status in connector.get_task_status_async(QUEUE_ID)]

    assert error.value.status_code == 404


async def test_unknown_or_removed_id_raises_the_server_message_with_requests():
    connector = SandboxConnector.windows('key', enable_requests=True)
    response = MagicMock(status_code=404, headers={'Content-Type': 'application/json; charset=utf-8'})
    response.json.return_value = {'error': True, 'message': 'Task not found'}
    connector._make_request_async = AsyncMock(return_value=response)

    with pytest.raises(RunTimeException, match='Task not found') as error:
        [status async for status in connector.get_task_status_async(QUEUE_ID)]

    assert error.value.status_code == 404


# ---------- listing the queue ----------

async def test_get_queued_tasks_returns_the_items_as_the_api_sends_them():
    connector = SandboxConnector.windows('key')

    with patch.object(connector, '_make_request_async', new_callable=AsyncMock, return_value=QUEUE_LIST_RESPONSE) as request:
        tasks = await connector.get_queued_tasks_async()

    assert tasks == QUEUE_LIST_RESPONSE['data']
    assert [task['tasksAhead'] for task in tasks] == [0, 1]
    request.assert_awaited_once_with('GET', 'https://api.any.run/v1/analysis/queue')


async def test_get_queued_tasks_returns_an_empty_list_if_nothing_is_waiting():
    connector = SandboxConnector.windows('key')

    with patch.object(connector, '_make_request_async', new_callable=AsyncMock, return_value={'error': False, 'data': []}):
        assert await connector.get_queued_tasks_async() == []


async def test_get_queued_tasks_returns_an_empty_list_if_the_answer_has_no_data():
    connector = SandboxConnector.windows('key')

    with patch.object(connector, '_make_request_async', new_callable=AsyncMock, return_value={'error': False}):
        assert await connector.get_queued_tasks_async() == []


def test_sync_get_queued_tasks_delegates_to_the_async_method():
    connector = SandboxConnector.windows('key')

    with patch.object(connector, 'get_queued_tasks_async', new_callable=AsyncMock, return_value=['task']) as method:
        assert connector.get_queued_tasks() == ['task']

    method.assert_awaited_once_with()


async def test_get_queued_tasks_works_with_requests():
    connector = SandboxConnector.windows('key', enable_requests=True)
    response = MagicMock(status_code=200, headers={})
    response.json.return_value = QUEUE_LIST_RESPONSE

    with patch('requests.request', return_value=response) as request:
        assert await connector.get_queued_tasks_async() == QUEUE_LIST_RESPONSE['data']

    assert request.call_args.args[:2] == ('GET', 'https://api.any.run/v1/analysis/queue')


async def test_get_queued_tasks_sends_the_teamspace_scope_as_query_parameters():
    connector = SandboxConnector.windows('key', team_id='team', customer_id='customer')
    response = MagicMock(status=200, headers={})
    response.json = AsyncMock(return_value=QUEUE_LIST_RESPONSE)
    connector._session = MagicMock()
    connector._session.request = AsyncMock(return_value=response)

    await connector.get_queued_tasks_async()

    assert connector._session.request.call_args.kwargs['params'] == {'teamId': 'team', 'customerId': 'customer'}


async def test_get_queued_tasks_raises_the_server_message():
    connector = SandboxConnector.windows('key')
    response = MagicMock(status=403, headers={})
    response.json = AsyncMock(return_value={'error': True, 'message': 'API is disabled in your account'})
    connector._session = MagicMock()
    connector._session.request = AsyncMock(return_value=response)

    with pytest.raises(RunTimeException, match='API is disabled in your account'):
        await connector.get_queued_tasks_async()


# ---------- removing a task from the queue ----------


async def test_remove_task_from_queue_sends_delete_to_the_queue_endpoint():
    connector = SandboxConnector.windows('key')
    answer = {'error': False, 'message': 'Task removed from queue'}

    with patch.object(connector, '_make_request_async', new_callable=AsyncMock, return_value=answer) as request:
        assert await connector.remove_task_from_queue_async(QUEUE_ID) == answer

    request.assert_awaited_once_with('DELETE', f'https://api.any.run/v1/analysis/queue/{QUEUE_ID}')


def test_sync_remove_task_from_queue_delegates_to_the_async_method():
    connector = SandboxConnector.windows('key')

    with patch.object(connector, 'remove_task_from_queue_async', new_callable=AsyncMock, return_value={'error': False}) as method:
        assert connector.remove_task_from_queue(QUEUE_ID) == {'error': False}

    method.assert_awaited_once_with(QUEUE_ID)


@pytest.mark.parametrize(
    ('status', 'message'),
    [
        (404, 'Queued task not found'),
        (409, 'Task is no longer in the queue'),
        (400, 'Validation failed (uuid v 4 is expected)'),
    ],
)
async def test_remove_task_from_queue_raises_the_server_message(status, message):
    connector = SandboxConnector.windows('key')
    response = MagicMock(status=status, headers={})
    response.json = AsyncMock(return_value={'error': True, 'message': message})
    connector._session = MagicMock()
    connector._session.request = AsyncMock(return_value=response)

    with pytest.raises(RunTimeException, match=message.replace('(', r'\(').replace(')', r'\)')) as error:
        await connector.remove_task_from_queue_async(QUEUE_ID)

    assert str(status) in str(error.value)


async def test_remove_task_from_queue_does_not_add_the_teamspace_scope():
    connector = SandboxConnector.windows('key', team_id='team', customer_id='customer', case_id='case')
    response = MagicMock(status=202, headers={})
    response.json = AsyncMock(return_value={'error': False, 'message': 'Task removed from queue'})
    connector._session = MagicMock()
    connector._session.request = AsyncMock(return_value=response)

    await connector.remove_task_from_queue_async(QUEUE_ID)

    request = connector._session.request.call_args
    assert request.args[0] == 'DELETE'
    assert request.kwargs['json'] is None
    assert request.kwargs['params'] is None
    assert request.kwargs['data'] is None
