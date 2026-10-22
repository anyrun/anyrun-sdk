import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp

from anyrun.connectors import FeedsConnector, LookupConnector, SandboxConnector, YaraLookupConnector

SCOPE = {'teamId': 'team', 'customerId': 'customer'}
KWARGS = {'team_id': 'team', 'customer_id': 'customer'}


def run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def requests_response(status=200, content=b'', payload=None, lines=()):
    response = MagicMock(status_code=status, content=content, headers={})
    response.json.return_value = payload or {}
    response.iter_lines.return_value = iter(lines)
    return response


def aiohttp_connector(connector):
    session = MagicMock()
    response = MagicMock(status=200, headers={})
    response.json = AsyncMock(return_value={})
    session.request = AsyncMock(return_value=response)
    connector._session = session
    return session


def test_no_scope_by_default_leaves_every_request_untouched():
    connector = SandboxConnector.windows('key', enable_requests=True)
    assert connector.teamspace_scope == {}

    with patch('requests.request', return_value=requests_response()) as request:
        run(connector._make_request_async('POST', 'https://any.run', json={'a': 1}))
        assert (request.call_args.kwargs['json'], request.call_args.kwargs['params']) == ({'a': 1}, None)

        run(connector._make_request_async('GET', 'https://any.run', params={'limit': 1}))
        assert (request.call_args.kwargs['json'], request.call_args.kwargs['params']) == (None, {'limit': 1})

        run(connector._make_request_async('GET', 'https://any.run'))
        assert request.call_args.kwargs['params'] is None

        files = {'f': ('f', b'1')}
        run(connector._make_request_async('POST', 'https://any.run', json={'a': 1}, files=files))
        assert (request.call_args.kwargs['json'], request.call_args.kwargs['data']) == ({'a': 1}, None)


def test_no_scope_by_default_leaves_aiohttp_multipart_untouched():
    connector = SandboxConnector.windows('key')
    session = aiohttp_connector(connector)
    body = aiohttp.MultipartWriter('form-data')

    run(connector._make_request_async('POST', 'https://any.run', data=body))

    assert session.request.call_args.kwargs['data'] is body
    assert not body._parts


def test_post_scope_is_sent_in_json_body_without_mutating_the_caller_dict():
    connector = LookupConnector('key', enable_requests=True, **KWARGS)
    body = {'query': 'x'}

    with patch('requests.request', return_value=requests_response()) as request:
        run(connector._make_request_async('POST', 'https://any.run', json=body))

    assert request.call_args.kwargs['json'] == {'query': 'x', **SCOPE}
    assert request.call_args.kwargs['params'] is None
    assert body == {'query': 'x'}


def test_get_scope_is_sent_in_query_and_merged_with_existing_params():
    connector = FeedsConnector('key', enable_requests=True, **KWARGS)

    with patch('requests.request', return_value=requests_response()) as request:
        run(connector._make_request_async('GET', 'https://any.run', params={'limit': 1}))

    assert request.call_args.kwargs['params'] == {'limit': 1, **SCOPE}
    assert request.call_args.kwargs['json'] is None


def test_other_methods_and_unscoped_requests_are_left_untouched():
    connector = SandboxConnector.windows('key', enable_requests=True, **KWARGS)

    with patch('requests.request', return_value=requests_response()) as request:
        run(connector._make_request_async('DELETE', 'https://any.run'))
        assert request.call_args.kwargs['params'] is None and request.call_args.kwargs['json'] is None

        run(connector._make_request_async('GET', 'https://any.run', scoped=False))
        assert request.call_args.kwargs['params'] is None


def test_file_upload_scope_is_sent_as_form_fields_with_requests():
    connector = SandboxConnector.windows('key', enable_requests=True, case_id='case', **KWARGS)

    with patch('requests.request', return_value=requests_response()) as request:
        run(connector._make_request_async(
            'POST', 'https://any.run', json={'env_os': 'windows', 'user_tags': None}, files={'f': ('f', b'1')}
        ))

    assert request.call_args.kwargs['json'] is None
    assert request.call_args.kwargs['data'] == {'env_os': 'windows', **SCOPE, 'caseId': 'case'}


def test_file_upload_scope_is_appended_to_multipart_with_aiohttp():
    connector = SandboxConnector.windows('key', case_id='case', **KWARGS)
    session = aiohttp_connector(connector)
    body = aiohttp.MultipartWriter('form-data')

    run(connector._make_request_async('POST', 'https://any.run', data=body))

    sent = session.request.call_args.kwargs['data']
    names = [part[0].headers['Content-Disposition'] for part in sent._parts]
    assert any('name="teamId"' in name for name in names)
    assert any('name="customerId"' in name for name in names)
    assert any('name="caseId"' in name for name in names)


def test_aiohttp_scope_placement():
    connector = YaraLookupConnector('key', **KWARGS)
    session = aiohttp_connector(connector)

    run(connector._make_request_async('POST', 'https://any.run', json={'query': 'r'}))
    assert session.request.call_args.kwargs['json'] == {'query': 'r', **SCOPE}

    run(connector._make_request_async('GET', 'https://any.run'))
    assert session.request.call_args.kwargs['params'] == SCOPE


def test_threat_intelligence_connectors_do_not_accept_case_id():
    for connector in (LookupConnector, YaraLookupConnector, FeedsConnector):
        try:
            connector('key', case_id='case')
        except TypeError:
            continue
        raise AssertionError(f'{connector.__name__} accepted case_id')


def test_requests_stream_helpers_use_the_common_request_helper_and_keep_binary_intact():
    connector = SandboxConnector.windows('key', enable_requests=True)
    sample = b'PK\x03\x04\nbinary\n\x00'

    with patch('requests.request', return_value=requests_response(content=sample)) as request, \
            patch('requests.Session') as session:
        assert run(connector._download_sample('https://any.run', 'zip', 'uuid')) == sample

    assert request.call_count == 1
    session.assert_not_called()


def test_task_status_stream_uses_the_common_request_helper_and_skips_meta_lines():
    connector = SandboxConnector.windows('key', enable_requests=True, **KWARGS)
    response = requests_response(
        lines=[b'id: 1', b'event: status', b'data: {"task": {"status": 100, "remaining": 0}}', b'']
    )
    response.headers = {'Content-Type': 'text/event-stream'}

    async def collect():
        return [status async for status in connector.get_task_status_async('uuid')]

    with patch('requests.request', return_value=response) as request, patch('requests.Session') as session:
        statuses = run(collect())

    assert [s['status'] for s in statuses] == ['COMPLETED']
    assert request.call_args.kwargs['stream'] is True
    assert request.call_args.kwargs['params'] == SCOPE
    session.assert_not_called()
