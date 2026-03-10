import os as os_module
import tempfile

import pytest

from anyrun.connectors import SandboxConnector
from anyrun.utils.exceptions import RunTimeException
from tests.conftest import MockAiohttpClientResponse


@pytest.mark.asyncio
async def test_generate_multipart_request_body_correctly_saves_file_payload():
    connector = SandboxConnector.windows('mock_api_key')

    # Use filepath
    multipart_body = await connector._generate_multipart_request_body(
        filepath='tests/suspicious_file.txt'
    )

    body_iterator = iter(multipart_body)

    payload = next(body_iterator)[0]
    assert payload.headers.get('Content-Disposition').split('"')[3] == 'suspicious_file.txt'
    assert payload.decode() == 'malware'

    # Use file_content and filename
    multipart_body = await connector._generate_multipart_request_body(
        filename='suspicious_file.txt',
        file_content=b'malware'
    )

    body_iterator = iter(multipart_body)

    payload = next(body_iterator)[0]
    assert payload.headers.get('Content-Disposition').split('"')[3] == 'suspicious_file.txt'
    assert payload.decode() == 'malware'


@pytest.mark.asyncio
async def test_generate_multipart_request_body_deletes_none_and_false_parameters():
    connector = SandboxConnector.windows('mock_api_key')

    multipart_body = await connector._generate_multipart_request_body(
        filepath='tests/suspicious_file.txt',
        obj_ext_cmd=None,
        obj_ext_extension=False
    )

    body_iterator = iter(multipart_body)
    # Skip file payload
    next(body_iterator)

    parsed_body_payload = ','.join(
        [
            f'{payload[0].headers.get("Content-Disposition").split("=")[1]}:{payload[0].decode()}'
            for payload in body_iterator
        ]
    )

    # Check if obj_ext_cmd parameter is not in payload
    assert parsed_body_payload == '"obj_type":file'

@pytest.mark.asyncio
async def test_generate_request_body_deletes_none_and_false_parameters():
    connector = SandboxConnector.windows('mock_api_key')

    body = await connector._generate_request_body(
        'url',
        obj_ext_cmd=None,
        obj_ext_extension=False
    )

    assert 'obj_ext_cmd' not in body
    assert 'obj_ext_extension' not in body


@pytest.mark.asyncio
async def test_prepare_response_returns_a_valid_simplified_dict_if_simplify_is_specified():
    connector = SandboxConnector.windows('mock_api_key')

    response = await connector._prepare_response(
        b'data: {"task": {"status": 50, "remaining": "30.123123"}, "some_other_data": "hello!"}',
        True,
        'task_uuid'
    )

    assert response == {
        "status": "RUNNING",
        "seconds_remaining": "30.123123",
        "info": "For interactive analysis follow: https://app.any.run/tasks/task_uuid"
    }

@pytest.mark.asyncio
async def test_prepare_response_returns_an_entire_dict_if_simplify_is_not_specified():
    connector = SandboxConnector.windows('mock_api_key')


    response = await connector._prepare_response(
        b'data: {"task": {"status": 50, "remaining": "30.123123"}, "some_other_data": "hello!"}',
        False,
        'task_uuid'
    )

    assert response == {"task": {"status": 50, "remaining": "30.123123"}, "some_other_data": "hello!"}


@pytest.mark.asyncio
async def test_check_response_content_type_raises_exception_if_event_stream_content_is_not_received():
    connector = SandboxConnector.windows('mock_api_key')

    with pytest.raises(RunTimeException) as exception:
        await connector._check_response_content_type('application/json', MockAiohttpClientResponse('application/json'))

    assert exception.value.json == {'description': 'Error message', 'code': 401}


@pytest.mark.asyncio
async def test_check_response_content_type_returns_none_if_event_stream_content_is_received():
    connector = SandboxConnector.windows('mock_api_key')

    assert await connector._check_response_content_type('text/event-stream', MockAiohttpClientResponse('text/event-stream')) is None

@pytest.mark.asyncio
async def test_check_resolve_task_status_returns_correct_statuses():
    connector = SandboxConnector.windows('mock_api_key')

    assert await connector._resolve_task_status(-1) == 'FAILED'
    assert await connector._resolve_task_status(50) == 'RUNNING'
    assert await connector._resolve_task_status(100) == 'COMPLETED'
    assert await connector._resolve_task_status(21) == 'PREPARING'

@pytest.mark.asyncio
async def test_check_get_file_payload_returns_valid_payload_if_file_bytes_is_received():
    connector = SandboxConnector.windows('mock_api_key')

    payload, _ = await connector._get_file_payload(file_content=b'some text', filename='suspicious_file.txt')

    assert payload.decode() == 'some text'

@pytest.mark.asyncio
async def test_check_get_file_payload_returns_valid_payload_if_file_path_is_received():
    connector = SandboxConnector.windows('mock_api_key')

    payload, _ = await connector._get_file_payload(filepath='tests/suspicious_file.txt')

    assert payload.decode() == 'malware'

@pytest.mark.asyncio
async def test_check_get_file_payload_raises_exception_if_not_a_valid_file_path_is_received():
    connector = SandboxConnector.windows('mock_api_key')

    with pytest.raises(RunTimeException) as exception:
        await connector._get_file_payload(filepath='123')

    assert exception.value.description == 'Received not valid filepath: 123'

@pytest.mark.asyncio
async def test_set_task_object_type_returns_params_with_obj_type_rerun_if_rerun_task_id_is_specified():
    connector = SandboxConnector.windows('mock_api_key')

    params = await connector._set_task_object_type(
        {'task_rerun_uuid': 'some task uuid'},
        'url'
    )

    assert params.get('obj_type') == 'rerun'
    assert params.get('task_rerun_uuid') == 'some task uuid'

@pytest.mark.asyncio
async def test_set_task_object_type_returns_params_with_specified_obj_type_if_rerun_task_id_is_not_specified():
    connector = SandboxConnector.windows('mock_api_key')

    params = await connector._set_task_object_type(
        {'obj_url': 'https://any.run'},
        'url'
    )

    assert params.get('obj_type') == 'url'
    assert params.get('obj_url') == 'https://any.run'


@pytest.mark.asyncio
async def test_prepare_iocs_filters_by_reputation():
    connector = SandboxConnector.windows('mock_api_key')
    iocs = [
        {'reputation': 0, 'id': '1'},
        {'reputation': 1, 'id': '2'},
        {'reputation': 2, 'id': '3'},
    ]
    result = await connector._prepare_iocs(iocs, 'suspicious')
    assert len(result) == 2
    assert all(ioc['reputation'] in (1, 2) for ioc in result)

    result = await connector._prepare_iocs(iocs, 'malicious')
    assert len(result) == 1
    assert result[0]['reputation'] == 2


@pytest.mark.asyncio
async def test_prepare_iocs_raises_for_unknown_reputation():
    connector = SandboxConnector.windows('mock_api_key')
    from anyrun.utils.exceptions import RunTimeException
    with pytest.raises(RunTimeException) as exc_info:
        await connector._prepare_iocs([], 'invalid')
    assert 'Unspecified IOCs reputation' in exc_info.value.description


@pytest.mark.asyncio
async def test_extract_sample_url_raises_for_private_sample():
    connector = SandboxConnector.windows('mock_api_key')
    from anyrun.utils.exceptions import RunTimeException
    report = {
        'analysis': {
            'options': {'privateSample': 'false'},
            'content': {'mainObject': {'type': 'file', 'permanentUrl': 'https://example.com/file'}},
        }
    }
    with pytest.raises(RunTimeException) as exc_info:
        await connector._extract_sample_url(report)
    assert 'private' in exc_info.value.description.lower()


@pytest.mark.asyncio
async def test_extract_sample_url_raises_when_not_file():
    connector = SandboxConnector.windows('mock_api_key')
    from anyrun.utils.exceptions import RunTimeException
    report = {
        'analysis': {
            'options': {'privateSample': 'true'},
            'content': {'mainObject': {'type': 'url', 'permanentUrl': 'https://example.com'}},
        }
    }
    with pytest.raises(RunTimeException) as exc_info:
        await connector._extract_sample_url(report)
    assert 'file sample' in exc_info.value.description.lower()


@pytest.mark.asyncio
async def test_extract_sample_url_returns_url_when_valid():
    connector = SandboxConnector.windows('mock_api_key')
    report = {
        'analysis': {
            'options': {'privateSample': 'true'},
            'content': {'mainObject': {'type': 'file', 'permanentUrl': 'https://content.any.run/sample.zip'}},
        }
    }
    url = await connector._extract_sample_url(report)
    assert url == 'https://content.any.run/sample.zip'


@pytest.mark.asyncio
async def test_dump_response_content_binary():
    connector = SandboxConnector.windows('mock_api_key')
    with tempfile.TemporaryDirectory() as tmpdir:
        await connector._dump_response_content(b'binary data', tmpdir, 'task-1', 'pcap')
        path = os_module.path.join(tmpdir, 'task-1_network_traffic_dump.zip')
        assert os_module.path.isfile(path)
        with open(path, 'rb') as f:
            assert f.read() == b'binary data'


@pytest.mark.asyncio
async def test_dump_response_content_json():
    connector = SandboxConnector.windows('mock_api_key')
    with tempfile.TemporaryDirectory() as tmpdir:
        await connector._dump_response_content({'key': 'value'}, tmpdir, 'task-1', 'summary')
        path = os_module.path.join(tmpdir, 'task-1_report_summary.json')
        assert os_module.path.isfile(path)


@pytest.mark.asyncio
async def test_dump_response_content_html():
    connector = SandboxConnector.windows('mock_api_key')
    with tempfile.TemporaryDirectory() as tmpdir:
        await connector._dump_response_content('<html>report</html>', tmpdir, 'task-1', 'html')
        path = os_module.path.join(tmpdir, 'task-1_report.html')
        assert os_module.path.isfile(path)
        with open(path) as f:
            assert f.read() == '<html>report</html>'


@pytest.mark.asyncio
async def test_dump_response_content_binary_type():
    connector = SandboxConnector.windows('mock_api_key')
    with tempfile.TemporaryDirectory() as tmpdir:
        await connector._dump_response_content(b'traffic', tmpdir, 'task-1', 'binary')
        path = os_module.path.join(tmpdir, 'task-1_traffic')
        assert os_module.path.isfile(path)
        with open(path, 'rb') as f:
            assert f.read() == b'traffic'


@pytest.mark.asyncio
async def test_dump_response_content_zip():
    connector = SandboxConnector.windows('mock_api_key')
    with tempfile.TemporaryDirectory() as tmpdir:
        await connector._dump_response_content(b'zip content', tmpdir, 'task-1', 'zip')
        path = os_module.path.join(tmpdir, 'task-1_file_sample.zip')
        assert os_module.path.isfile(path)


@pytest.mark.asyncio
async def test_get_file_payload_raises_when_no_file_specified():
    connector = SandboxConnector.windows('mock_api_key')
    with pytest.raises(RunTimeException) as exc_info:
        await connector._get_file_payload()
    assert 'file_content with filename or filepath' in exc_info.value.description


@pytest.mark.asyncio
async def test_check_response_content_type_raises_for_unspecified_stream_error():
    connector = SandboxConnector.windows('mock_api_key')
    mock_response = type('R', (), {'status': 500, 'status_code': 500})()
    with pytest.raises(RunTimeException) as exc_info:
        await connector._check_response_content_type('text/plain', mock_response)
    assert 'unspecified error' in exc_info.value.description.lower()
