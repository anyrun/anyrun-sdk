"""
Helpers that run the Sandbox connectors with the real request encoding and return what would go over the wire.

The requests package silently drops `json` when `files` are sent, so every transport has to be checked separately:
file uploads are inspected through requests.Session.send / the aiohttp multipart writer, and JSON bodies through
the arguments of the HTTP call.
"""
import asyncio
import re
from unittest.mock import AsyncMock, MagicMock, patch

import requests

from anyrun.connectors import SandboxConnector

OS_CONNECTORS = {
    'windows': SandboxConnector.windows,
    'linux': SandboxConnector.linux,
    'android': SandboxConnector.android,
    'macos': SandboxConnector.macos,
}
SCOPES = [{}, {'team_id': 'team', 'customer_id': 'customer'}]
JSON_METHODS = {
    'run_url_analysis_async': {'obj_url': 'https://example.com'},
    'run_download_analysis_async': {'obj_url': 'https://example.com/file.exe'},
}


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


def send_with_aiohttp(connector, **kwargs) -> dict[str, str]:
    """Runs run_file_analysis_async with the aiohttp transport and returns the sent form fields"""
    response = MagicMock(status=200, headers={})
    response.json = AsyncMock(return_value={'data': {'taskid': 'task-id'}})
    connector._session = MagicMock()
    connector._session.request = AsyncMock(return_value=response)

    run(connector.run_file_analysis_async(**kwargs))

    body = connector._session.request.call_args.kwargs['data']
    fields = {}
    for part in body._parts:
        name = re.search(r'name="([^"]+)"', part[0].headers['Content-Disposition']).group(1)
        fields[name] = part[0]._value.decode(errors='replace') if isinstance(part[0]._value, bytes) else None
    return fields


def json_body_with_requests(connector, method_name: str, **kwargs) -> dict:
    """Runs a JSON-body run_*_analysis_async method in the requests mode and returns the sent JSON"""
    response = MagicMock(status_code=201, headers={})
    response.json.return_value = {'data': {'taskid': 'task-id'}}

    with patch('requests.request', return_value=response) as request:
        run(getattr(connector, method_name)(**kwargs))

    return request.call_args.kwargs['json']


def json_body_with_aiohttp(connector, method_name: str, **kwargs) -> dict:
    """Runs a JSON-body run_*_analysis_async method in the aiohttp mode and returns the sent JSON"""
    response = MagicMock(status=201, headers={})
    response.json = AsyncMock(return_value={'data': {'taskid': 'task-id'}})
    connector._session = MagicMock()
    connector._session.request = AsyncMock(return_value=response)

    run(getattr(connector, method_name)(**kwargs))

    return connector._session.request.call_args.kwargs['json']
