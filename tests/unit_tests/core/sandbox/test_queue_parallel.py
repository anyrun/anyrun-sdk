"""
Tests for the queue_parallel option of the run_*_analysis methods.

The server queues a task only if the option is sent, and reads it from a file upload only as the lowercase
string "true" ("True" is silently ignored). Payloads below are copies of real API responses.
"""
import inspect
from unittest.mock import AsyncMock, MagicMock

import pytest

from anyrun.connectors import SandboxConnector
from anyrun.utils.exceptions import RunTimeException
from anyrun.utils.utility_functions import check_if_analysis_initialized, is_queue_parallel_enabled
from tests.unit_tests.core.sandbox.wire_helpers import (
    JSON_METHODS,
    OS_CONNECTORS,
    SCOPES,
    json_body_with_aiohttp,
    json_body_with_requests,
    run,
    send_with_aiohttp,
    send_with_requests,
)

QUEUE_ID = '98115696-868d-4abd-bd3e-033a2e327aeb'
QUEUED_MESSAGES = [
    'Task is queued and awaits execution. To track its status, call GET /v1/analysis/monitor/{queueTaskId}.',
    'Task will be launched soon. To track its status, call GET /v1/analysis/monitor/{queueTaskId}.',
]
ANALYSIS_METHODS = {
    'run_file_analysis_async': {'file_content': b'abc', 'filename': 'a.txt'},
    **JSON_METHODS,
}


def queued_response(message: str) -> dict:
    return {'error': False, 'message': message, 'data': {'queueTaskId': QUEUE_ID}}


# ---------- what goes over the wire ----------

@pytest.mark.parametrize('os_name', OS_CONNECTORS)
@pytest.mark.parametrize('method_name', JSON_METHODS)
@pytest.mark.parametrize('transport', [json_body_with_aiohttp, json_body_with_requests])
def test_json_analysis_does_not_send_queue_parallel_by_default(os_name, method_name, transport):
    connector = OS_CONNECTORS[os_name]('key', enable_requests=transport is json_body_with_requests)

    body = transport(connector, method_name, **JSON_METHODS[method_name])

    assert 'queue_parallel' not in body


@pytest.mark.parametrize('os_name', OS_CONNECTORS)
@pytest.mark.parametrize('method_name', JSON_METHODS)
@pytest.mark.parametrize('transport', [json_body_with_aiohttp, json_body_with_requests])
def test_json_analysis_sends_queue_parallel_as_json_boolean(os_name, method_name, transport):
    connector = OS_CONNECTORS[os_name]('key', enable_requests=transport is json_body_with_requests)

    body = transport(connector, method_name, queue_parallel=True, **JSON_METHODS[method_name])

    assert body['queue_parallel'] is True


@pytest.mark.parametrize('os_name', OS_CONNECTORS)
@pytest.mark.parametrize('scope', SCOPES)
@pytest.mark.parametrize('enable_requests', [False, True])
def test_file_analysis_does_not_send_queue_parallel_by_default(os_name, scope, enable_requests):
    connector = OS_CONNECTORS[os_name]('key', enable_requests=enable_requests, **scope)
    send = send_with_requests if enable_requests else send_with_aiohttp

    fields = send(connector, file_content=b'abc', filename='a.txt')

    assert 'queue_parallel' not in fields


@pytest.mark.parametrize('os_name', OS_CONNECTORS)
@pytest.mark.parametrize('scope', SCOPES)
@pytest.mark.parametrize('enable_requests', [False, True])
def test_file_analysis_sends_queue_parallel_as_lowercase_string(os_name, scope, enable_requests):
    connector = OS_CONNECTORS[os_name]('key', enable_requests=enable_requests, **scope)
    send = send_with_requests if enable_requests else send_with_aiohttp

    fields = send(connector, file_content=b'abc', filename='a.txt', queue_parallel=True)

    # The server ignores "True" for this field, so the SDK must not rely on str(True)
    assert fields['queue_parallel'] == 'true'


@pytest.mark.parametrize('os_name', OS_CONNECTORS)
def test_other_boolean_options_keep_their_spelling_when_queue_parallel_is_enabled(os_name):
    connector = OS_CONNECTORS[os_name]('key')

    fields = send_with_aiohttp(connector, file_content=b'abc', filename='a.txt', queue_parallel=True)

    assert fields['opt_network_connect'] == 'True'
    assert fields['opt_network_fakenet'] == 'False'


# ---------- what the run methods return ----------

@pytest.mark.parametrize('message', QUEUED_MESSAGES)
@pytest.mark.parametrize('method_name', ANALYSIS_METHODS)
@pytest.mark.parametrize('os_name', OS_CONNECTORS)
async def test_run_analysis_returns_queue_id_if_the_task_was_queued(os_name, method_name, message):
    connector = OS_CONNECTORS[os_name]('key')
    connector._make_request_async = AsyncMock(return_value=queued_response(message))

    result = await getattr(connector, method_name)(**ANALYSIS_METHODS[method_name], queue_parallel=True)

    assert result == QUEUE_ID


@pytest.mark.parametrize('method_name', ANALYSIS_METHODS)
@pytest.mark.parametrize('os_name', OS_CONNECTORS)
async def test_run_analysis_still_raises_if_the_task_was_queued_without_queue_parallel(os_name, method_name):
    connector = OS_CONNECTORS[os_name]('key')
    connector._make_request_async = AsyncMock(return_value=queued_response(QUEUED_MESSAGES[0]))

    with pytest.raises(RunTimeException, match=QUEUE_ID):
        await getattr(connector, method_name)(**ANALYSIS_METHODS[method_name])


@pytest.mark.parametrize('method_name', ANALYSIS_METHODS)
@pytest.mark.parametrize('os_name', OS_CONNECTORS)
async def test_run_analysis_returns_task_id_if_the_task_started_with_queue_parallel_enabled(os_name, method_name):
    connector = OS_CONNECTORS[os_name]('key')
    connector._make_request_async = AsyncMock(return_value={'error': False, 'data': {'taskid': 'task-id'}})

    result = await getattr(connector, method_name)(**ANALYSIS_METHODS[method_name], queue_parallel=True)

    assert result == 'task-id'


def test_sync_run_analysis_forwards_queue_parallel_and_returns_queue_id():
    connector = SandboxConnector.windows('key')
    connector._make_request_async = AsyncMock(return_value=queued_response(QUEUED_MESSAGES[0]))

    assert connector.run_url_analysis('https://example.com', queue_parallel=True) == QUEUE_ID
    assert connector.run_download_analysis('https://example.com/file.exe', queue_parallel=True) == QUEUE_ID
    assert connector.run_file_analysis(file_content=b'abc', filename='a.txt', queue_parallel=True) == QUEUE_ID


@pytest.mark.parametrize('method_name', ANALYSIS_METHODS)
@pytest.mark.parametrize('queue_parallel', [True, False])
async def test_run_analysis_raises_the_server_message_if_the_parallel_limit_is_reached(method_name, queue_parallel):
    connector = SandboxConnector.windows('key')
    response = MagicMock(status=429, headers={})
    response.json = AsyncMock(return_value={'error': True, 'message': 'Parallel task limit'})
    connector._session = MagicMock()
    connector._session.request = AsyncMock(return_value=response)

    with pytest.raises(RunTimeException, match='Parallel task limit') as error:
        await getattr(connector, method_name)(**ANALYSIS_METHODS[method_name], queue_parallel=queue_parallel)

    assert '429' in str(error.value)


# ---------- the decorator ----------

def test_run_methods_accept_queue_parallel_as_the_last_parameter_and_disabled_by_default():
    for os_name, factory in OS_CONNECTORS.items():
        connector = factory('key')
        for method_name in ('run_file_analysis', 'run_url_analysis', 'run_download_analysis'):
            for name in (method_name, f'{method_name}_async'):
                parameters = inspect.signature(getattr(connector, name)).parameters
                assert list(parameters)[-1] == 'queue_parallel', f'{os_name}.{name}'
                assert parameters['queue_parallel'].default is False, f'{os_name}.{name}'


def test_is_queue_parallel_enabled_reads_positional_keyword_and_default_values():
    def function(self, value, queue_parallel=False):
        pass

    signature = inspect.signature(function)

    assert is_queue_parallel_enabled(signature, (None, 1, True), {}) is True
    assert is_queue_parallel_enabled(signature, (None, 1), {'queue_parallel': True}) is True
    assert is_queue_parallel_enabled(signature, (None, 1), {}) is False
    assert is_queue_parallel_enabled(signature, (None, 1, False), {}) is False


def test_check_if_analysis_initialized_works_for_a_function_without_queue_parallel():
    @check_if_analysis_initialized
    async def function(self):
        return queued_response(QUEUED_MESSAGES[0])

    with pytest.raises(RunTimeException, match=QUEUE_ID):
        run(function(None))


def test_check_if_analysis_initialized_returns_queue_id_if_queue_parallel_is_passed_positionally():
    @check_if_analysis_initialized
    async def function(self, value, queue_parallel=False):
        return queued_response(QUEUED_MESSAGES[0])

    assert run(function(None, 1, True)) == QUEUE_ID
