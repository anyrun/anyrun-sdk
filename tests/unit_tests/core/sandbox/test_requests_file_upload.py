"""
Regression tests for file submissions in the enable_requests mode.

The requests package silently drops `json` when `files` are sent, so the analysis options must be
sent as multipart form fields. These tests stub requests.Session.send so the real requests body
encoding runs and the test checks what actually goes over the wire.
"""
import asyncio
import re
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import requests

from anyrun.connectors import SandboxConnector
from anyrun.utils.utility_functions import drop_empty_values

OS_CONNECTORS = {
    'windows': SandboxConnector.windows,
    'linux': SandboxConnector.linux,
    'android': SandboxConnector.android,
    'macos': SandboxConnector.macos,
}
SCOPES = [{}, {'team_id': 'team', 'customer_id': 'customer'}]


def run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def parse_multipart_fields(body: bytes) -> dict[str, str]:
    """Returns {field name: value} for every part of an encoded multipart body"""
    fields = {}
    for name, value in re.findall(rb'name="([^"]+)"(?:; filename="[^"]*")?\r\n(?:[^\r\n]+\r\n)*\r\n(.*?)\r\n--', body, re.S):
        fields[name.decode()] = value.decode(errors='replace')
    return fields


def send_with_requests(connector, **kwargs) -> dict[str, str]:
    """Runs run_file_analysis_async with the real requests encoding and returns the sent form fields"""
    sent = {}

    def fake_send(self, prepared, **_):
        sent['body'] = prepared.body
        response = requests.Response()
        response.status_code = 200
        response._content = b'{"error": false, "data": {"taskid": "task-id"}}'
        return response

    with patch.object(requests.Session, 'send', fake_send):
        assert run(connector.run_file_analysis_async(**kwargs)) == 'task-id'

    return parse_multipart_fields(sent['body'])


def send_with_aiohttp(connector, **kwargs) -> set[str]:
    """Runs run_file_analysis_async with the aiohttp transport and returns the sent form field names"""
    response = MagicMock(status=200, headers={})
    response.json = AsyncMock(return_value={'data': {'taskid': 'task-id'}})
    connector._session = MagicMock()
    connector._session.request = AsyncMock(return_value=response)

    run(connector.run_file_analysis_async(**kwargs))

    body = connector._session.request.call_args.kwargs['data']
    names = set()
    for part in body._parts:
        names.add(re.search(r'name="([^"]+)"', part[0].headers['Content-Disposition']).group(1))
    return names


@pytest.mark.parametrize('os_name', OS_CONNECTORS)
@pytest.mark.parametrize('scope', SCOPES)
def test_requests_file_upload_sends_analysis_options_as_form_fields(os_name, scope):
    connector = OS_CONNECTORS[os_name]('key', enable_requests=True, **scope)

    fields = send_with_requests(
        connector, file_content=b'MZ\x00binary', filename='sample.exe', opt_timeout=120, opt_privacy_type='owner',
    )

    assert fields['file'] == 'MZ\x00binary'
    assert fields['env_os'] == os_name
    assert fields['obj_type'] == 'file'
    assert fields['opt_timeout'] == '120'
    assert fields['opt_privacy_type'] == 'owner'
    assert fields['opt_network_tor'] == 'False'
    assert 'user_tags' not in fields
    assert 'task_rerun_uuid' not in fields
    for field, value in {'teamId': 'team', 'customerId': 'customer'}.items():
        assert (fields.get(field) == value) if scope else (field not in fields)


@pytest.mark.parametrize('os_name', OS_CONNECTORS)
def test_requests_file_upload_sets_rerun_object_type(os_name):
    connector = OS_CONNECTORS[os_name]('key', enable_requests=True)

    fields = send_with_requests(connector, file_content=b'abc', filename='a.txt', task_rerun_uuid='rerun-id')

    assert fields['obj_type'] == 'rerun'
    assert fields['task_rerun_uuid'] == 'rerun-id'


@pytest.mark.parametrize('os_name', OS_CONNECTORS)
@pytest.mark.parametrize('scope', SCOPES)
def test_requests_and_aiohttp_file_uploads_send_the_same_fields(os_name, scope):
    kwargs = {'file_content': b'abc', 'filename': 'a.txt', 'user_tags': 'tag', 'opt_timeout': 30}

    requests_fields = set(send_with_requests(OS_CONNECTORS[os_name]('key', enable_requests=True, **scope), **kwargs))
    aiohttp_fields = send_with_aiohttp(OS_CONNECTORS[os_name]('key', **scope), **kwargs)

    assert requests_fields == aiohttp_fields


def test_drop_empty_values_keeps_booleans_and_zero_but_drops_none_and_empty_strings():
    params = {'none': None, 'empty': '', 'false': False, 'true': True, 'zero': 0, 'value': 'x'}

    assert drop_empty_values(params) == {'false': False, 'true': True, 'zero': 0, 'value': 'x'}
    assert params['none'] is None
