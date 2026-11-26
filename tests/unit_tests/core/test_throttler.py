import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from anyrun.connectors.base_connector import AnyRunConnector
from anyrun.connectors.sandbox.base_connector import BaseSandboxConnector
from anyrun.connectors.sandbox.operation_systems.windows import WindowsConnector
from anyrun.connectors.threat_intelligence.lookup_connector import LookupConnector
from anyrun.utils import throttler
from anyrun.utils.config import Config
from anyrun.utils.exceptions import RunTimeException
from anyrun.utils.throttler import ThrottledException

API_KEY = 'mock_api_key_1234567890'


@pytest.fixture(autouse=True)
def clean_storage(monkeypatch):
    throttler.THROTTLE_STORAGE.clear()
    throttler._PROBING.clear()
    monkeypatch.setattr(Config, 'ENABLE_THROTTLING', True)
    yield
    throttler.THROTTLE_STORAGE.clear()
    throttler._PROBING.clear()


def make_connector(statuses: list, connector_class: type = AnyRunConnector, **kwargs) -> AnyRunConnector:
    """Connector whose fake session answers with the given (status, message) pairs one by one."""
    responses = []
    for status, message in statuses:
        response = MagicMock()
        response.status = status
        response.headers = {}
        response.json = AsyncMock(return_value={'message': message, 'data': {'limits': {}, 'taskid': 'mock_uuid'}})
        responses.append(response)

    connector = connector_class(API_KEY, **kwargs)
    connector._session = MagicMock()
    connector._session.request = AsyncMock(side_effect=responses)
    return connector


async def request(connector: AnyRunConnector):
    return await connector._make_request_async('GET', 'https://any.run')


async def other_request(connector: AnyRunConnector):
    return await connector._make_request_async('GET', 'https://any.run')


@pytest.mark.parametrize(
    'status, message',
    [
        (403, 'Authorization required'),
        (403, 'Wrong authorization data'),
        (403, "We can't recognize you! Please contact us support@any.run"),
        (403, 'API is not available on the free plan'),
        (403, 'API is disabled in your account'),
        (401, 'Error message'),
        (429, 'Too many requests'),
    ],
)
async def test_key_is_throttled_after_the_first_license_related_error(status, message):
    connector = make_connector([(status, message)])

    with pytest.raises(RunTimeException) as first:
        await request(connector)
    assert first.value.status_code == status
    assert not isinstance(first.value, ThrottledException)

    with pytest.raises(ThrottledException):
        await request(connector)

    assert connector._session.request.await_count == 1
    assert len(throttler.THROTTLE_STORAGE) == 1


@pytest.mark.parametrize(
    'status, message',
    [
        (403, 'Requires an active subscription to a Hunter or Enterprise plan'),
        (403, 'Private content'),
        (403, "You can't access to this task"),
        (403, 'You must use your personal login data or API key for this type of request'),
        (400, 'This feature is not available for your plan'),
        (404, 'Task not found'),
        (429, 'Parallel task limit'),
        (429, 'AI Summary limit exceeded'),
    ],
)
async def test_key_is_not_throttled_by_feature_specific_errors(status, message):
    connector = make_connector([(status, message)] * 2)

    for _ in range(2):
        with pytest.raises(RunTimeException) as exception:
            await request(connector)
        assert not isinstance(exception.value, ThrottledException)

    assert connector._session.request.await_count == 2
    assert not throttler.THROTTLE_STORAGE


async def test_throttling_does_nothing_if_it_is_disabled_in_config(monkeypatch):
    monkeypatch.setattr(Config, 'ENABLE_THROTTLING', False)
    connector = make_connector([(403, 'Authorization required')] * 2)

    for _ in range(2):
        with pytest.raises(RunTimeException):
            await request(connector)

    assert connector._session.request.await_count == 2
    assert not throttler.THROTTLE_STORAGE


async def test_storage_does_not_keep_the_api_key():
    connector = make_connector([(403, 'Authorization required')])

    with pytest.raises(RunTimeException):
        await request(connector)

    assert all(API_KEY not in key and API_KEY[:5] not in key for key in throttler.THROTTLE_STORAGE)


async def test_throttle_is_shared_between_connectors_with_the_same_key():
    with pytest.raises(RunTimeException):
        await request(make_connector([(403, 'Authorization required')]))

    other = make_connector([(200, 'ok')])
    with pytest.raises(ThrottledException):
        await request(other)
    assert other._session.request.await_count == 0


async def unparsed_request(connector: AnyRunConnector):
    return await connector._make_request_async('GET', 'https://any.run', parse_response=False)


async def anext_item(iterator):
    return await iterator.__anext__()


async def test_log_shows_only_the_edges_of_the_key_without_its_prefix(capsys):
    with pytest.raises(RunTimeException):
        await request(make_connector([(403, 'Authorization required')]))

    output = capsys.readouterr().out
    assert 'mock_..67890' in output
    assert API_KEY not in output


async def test_throttle_is_shared_between_callers_from_one_module():
    connector = make_connector([(403, 'Authorization required')])
    with pytest.raises(RunTimeException):
        await request(connector)

    with pytest.raises(ThrottledException):
        await other_request(connector)
    assert connector._session.request.await_count == 1


@pytest.mark.parametrize(
    'connector_class, first, second',
    [
        (
            BaseSandboxConnector,
            lambda connector: connector.get_user_limits_async(),
            lambda connector: connector.get_analysis_history_async(),
        ),
        (
            LookupConnector,
            lambda connector: connector.check_authorization_async(),
            lambda connector: connector.get_intelligence_async(query='threatName:mock'),
        ),
    ],
    ids=['sandbox', 'ti_lookup'],
)
async def test_throttle_covers_all_methods_of_a_connector_module(connector_class, first, second):
    connector = make_connector([(403, 'Authorization required')], connector_class)
    with pytest.raises(RunTimeException):
        await first(connector)

    with pytest.raises(ThrottledException):
        await second(connector)
    assert connector._session.request.await_count == 1


async def test_inherited_and_own_methods_of_a_connector_are_throttled_separately():
    """The throttle belongs to the module which defines the method, not to the class of the connector."""
    connector = make_connector([(403, 'Authorization required'), (200, 'ok')], WindowsConnector)
    with pytest.raises(RunTimeException):
        await connector.get_user_limits_async()  # sandbox/base_connector.py

    await connector.run_url_analysis_async(obj_url='https://any.run')  # sandbox/operation_systems/windows.py

    assert connector._session.request.await_count == 2


async def test_storage_key_consists_of_root_url_module_and_key_hash():
    with pytest.raises(RunTimeException):
        await make_connector([(403, 'Authorization required')], BaseSandboxConnector).get_user_limits_async()

    root_url, module, key_hash = next(iter(throttler.THROTTLE_STORAGE)).split(':')
    assert root_url == 'any.run'
    assert module == 'anyrun.connectors.sandbox.base_connector'
    assert len(key_hash) == 64


async def test_throttle_on_one_root_url_does_not_block_other_root_urls():
    wrong_region = make_connector([(403, 'Wrong authorization data')], root_url='eu.mock.run')
    right_region = make_connector([(200, 'ok')], root_url='any.run')
    with pytest.raises(RunTimeException):
        await request(wrong_region)

    await request(right_region)

    with pytest.raises(ThrottledException):
        await request(wrong_region)
    assert wrong_region._session.request.await_count == 1
    assert right_region._session.request.await_count == 1


async def test_missing_ti_license_does_not_block_the_sandbox():
    ti = make_connector([(403, 'API is not available on the free plan')], LookupConnector)
    sandbox = make_connector([(200, 'ok')], BaseSandboxConnector)

    with pytest.raises(RunTimeException):
        await ti.get_intelligence_async(query='threatName:mock')
    with pytest.raises(ThrottledException):
        await ti.get_intelligence_async(query='threatName:mock')

    await sandbox.get_user_limits_async()

    assert ti._session.request.await_count == 1
    assert sandbox._session.request.await_count == 1


async def test_throttle_is_removed_after_ttl_if_the_probe_request_succeeds(monkeypatch):
    connector = make_connector([(403, 'Authorization required'), (200, 'ok'), (200, 'ok')])
    with pytest.raises(RunTimeException):
        await request(connector)

    monkeypatch.setattr(Config, 'THROTTLE_TTL_IN_SECONDS', 0)

    await request(connector)
    assert not throttler.THROTTLE_STORAGE
    assert not throttler._PROBING

    await request(connector)
    assert connector._session.request.await_count == 3


async def test_key_is_throttled_again_if_the_probe_request_fails(monkeypatch):
    connector = make_connector([(403, 'Authorization required'), (403, 'Authorization required')])
    with pytest.raises(RunTimeException):
        await request(connector)

    monkeypatch.setattr(Config, 'THROTTLE_TTL_IN_SECONDS', 0)
    with pytest.raises(RunTimeException) as exception:
        await request(connector)
    assert not isinstance(exception.value, ThrottledException)

    monkeypatch.setattr(Config, 'THROTTLE_TTL_IN_SECONDS', 1800)
    with pytest.raises(ThrottledException):
        await request(connector)
    assert not throttler._PROBING


async def test_only_one_probe_request_is_sent_after_ttl(monkeypatch):
    connector = make_connector([(403, 'Authorization required')])
    with pytest.raises(RunTimeException):
        await request(connector)

    monkeypatch.setattr(Config, 'THROTTLE_TTL_IN_SECONDS', 0)

    started, release = asyncio.Event(), asyncio.Event()
    response = MagicMock(status=200, headers={})
    response.json = AsyncMock(return_value={'message': 'ok'})

    async def slow_request(*args, **kwargs):
        started.set()
        await release.wait()
        return response

    connector._session.request = AsyncMock(side_effect=slow_request)

    probe = asyncio.create_task(request(connector))
    await started.wait()

    with pytest.raises(ThrottledException):
        await request(connector)

    release.set()
    await probe
    assert connector._session.request.await_count == 1
    assert not throttler.THROTTLE_STORAGE


async def test_http_error_status_is_preserved_in_the_raised_exception():
    connector = make_connector([(404, 'Task not found')])

    with pytest.raises(RunTimeException) as exception:
        await request(connector)

    assert exception.value.status_code == 404
    assert exception.value.description == 'Task not found'


@pytest.mark.parametrize(
    'call',
    [
        lambda sandbox: sandbox.get_analysis_report_async('mock_uuid', report_format='html'),
        lambda sandbox: sandbox.get_analysis_report_async('mock_uuid', report_format='tier1-html'),
        lambda sandbox: sandbox._download_sample('https://any.run', 'zip', 'mock_uuid'),
        lambda sandbox: anext_item(sandbox.get_task_status_async('mock_uuid')),
    ],
    ids=['html_report', 'tier1_html_report', 'sample_download', 'status_stream'],
)
async def test_error_status_of_unparsed_requests_causes_a_throttle(call):
    sandbox = make_connector([(403, 'Authorization required')], BaseSandboxConnector)

    with pytest.raises(RunTimeException) as first:
        await call(sandbox)
    assert first.value.status_code == 403
    assert first.value.description == 'Authorization required'

    with pytest.raises(ThrottledException):
        await call(sandbox)
    assert sandbox._session.request.await_count == 1


async def test_unparsed_429_with_a_non_json_body_causes_a_throttle():
    connector = make_connector([(429, 'unused')])
    response = MagicMock(status=429, headers={})
    response.json = AsyncMock(side_effect=ValueError('not a json'))
    connector._session.request = AsyncMock(return_value=response)

    with pytest.raises(RunTimeException) as exception:
        await unparsed_request(connector)
    assert exception.value.status_code == 429

    with pytest.raises(ThrottledException):
        await unparsed_request(connector)


async def test_error_status_of_unparsed_requests_throttles_with_the_requests_package(monkeypatch):
    response = MagicMock(status_code=403, headers={})
    response.json.return_value = {'message': 'Authorization required'}
    send = MagicMock(return_value=response)
    monkeypatch.setattr('anyrun.connectors.base_connector.requests.request', send)
    connector = AnyRunConnector(API_KEY, enable_requests=True)

    with pytest.raises(RunTimeException):
        await unparsed_request(connector)
    with pytest.raises(ThrottledException):
        await unparsed_request(connector)

    assert send.call_count == 1


async def test_failed_unparsed_probe_request_throttles_again(monkeypatch):
    connector = make_connector([(403, 'Authorization required'), (403, 'Authorization required')])
    with pytest.raises(RunTimeException):
        await unparsed_request(connector)

    monkeypatch.setattr(Config, 'THROTTLE_TTL_IN_SECONDS', 0)
    with pytest.raises(RunTimeException):
        await unparsed_request(connector)

    monkeypatch.setattr(Config, 'THROTTLE_TTL_IN_SECONDS', 1800)
    with pytest.raises(ThrottledException):
        await unparsed_request(connector)


async def test_unparsed_error_response_is_returned_as_is_if_throttling_is_disabled(monkeypatch):
    monkeypatch.setattr(Config, 'ENABLE_THROTTLING', False)
    connector = make_connector([(403, 'Authorization required')])

    response = await unparsed_request(connector)

    assert response.status == 403


async def test_proxy_check_is_never_throttled():
    connector = make_connector([(429, 'Too many requests')] * 2)

    for _ in range(2):
        assert (await connector.check_proxy_async())['status'] == 'ok'

    assert not throttler.THROTTLE_STORAGE

