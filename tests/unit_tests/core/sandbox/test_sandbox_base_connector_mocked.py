"""Unit tests for sandbox base connector with mocked HTTP."""

import os as os_module
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from anyrun.connectors import SandboxConnector


@pytest.mark.asyncio
async def test_get_analysis_history_async():
    connector = SandboxConnector.windows('mock_api_key')
    with patch.object(connector, '_make_request_async', new_callable=AsyncMock,
                      return_value={'data': {'tasks': [{'taskid': '1'}]}}):
        async with connector:
            result = await connector.get_analysis_history_async()
        assert result == [{'taskid': '1'}]


@pytest.mark.asyncio
async def test_get_analysis_report_async_summary():
    connector = SandboxConnector.windows('mock_api_key')
    with patch.object(connector, '_make_request_async', new_callable=AsyncMock,
                      return_value={'data': {'analysis': {}}}):
        async with connector:
            result = await connector.get_analysis_report_async('task-uuid', report_format='summary')
        assert 'data' in result


@pytest.mark.asyncio
async def test_add_time_to_task_async():
    connector = SandboxConnector.windows('mock_api_key')
    with patch.object(connector, '_make_request_async', new_callable=AsyncMock, return_value={'ok': True}):
        async with connector:
            result = await connector.add_time_to_task_async('task-uuid')
        assert result == {'ok': True}


@pytest.mark.asyncio
async def test_stop_task_async():
    connector = SandboxConnector.windows('mock_api_key')
    with patch.object(connector, '_make_request_async', new_callable=AsyncMock, return_value={'ok': True}):
        async with connector:
            result = await connector.stop_task_async('task-uuid')
        assert result == {'ok': True}


@pytest.mark.asyncio
async def test_delete_task_async():
    connector = SandboxConnector.windows('mock_api_key')
    with patch.object(connector, '_make_request_async', new_callable=AsyncMock, return_value={'ok': True}):
        async with connector:
            result = await connector.delete_task_async('task-uuid')
        assert result == {'ok': True}


@pytest.mark.asyncio
async def test_get_user_environment_async():
    connector = SandboxConnector.windows('mock_api_key')
    with patch.object(connector, '_make_request_async', new_callable=AsyncMock, return_value={'data': {}}):
        async with connector:
            result = await connector.get_user_environment_async()
        assert 'data' in result


@pytest.mark.asyncio
async def test_get_user_limits_async():
    connector = SandboxConnector.windows('mock_api_key')
    with patch.object(connector, '_make_request_async', new_callable=AsyncMock,
                      return_value={'data': {'limits': {'daily': 10}}}):
        async with connector:
            result = await connector.get_user_limits_async()
        assert result == {'daily': 10}


@pytest.mark.asyncio
async def test_get_user_presets_async():
    connector = SandboxConnector.windows('mock_api_key')
    with patch.object(connector, '_make_request_async', new_callable=AsyncMock, return_value=[{'name': 'preset1'}]):
        async with connector:
            result = await connector.get_user_presets_async()
        assert result == [{'name': 'preset1'}]


@pytest.mark.asyncio
async def test_get_analysis_verdict_async():
    connector = SandboxConnector.windows('mock_api_key')
    with patch.object(connector, 'get_analysis_report_async', new_callable=AsyncMock,
                      return_value={'data': {'analysis': {'scores': {'verdict': {'threatLevelText': 'Malicious'}}}}}) as mock_report:
        async with connector:
            result = await connector.get_analysis_verdict_async('task-uuid')
        assert result == 'Malicious'


@pytest.mark.asyncio
async def test_download_pcap_async():
    connector = SandboxConnector.windows('mock_api_key')
    mock_content = b'pcap data'
    mock_response = AsyncMock()
    mock_response.content.read = AsyncMock(return_value=mock_content)
    with patch.object(connector, '_make_request_async', new_callable=AsyncMock, return_value=mock_response):
        async with connector:
            result = await connector.download_pcap_async('task-uuid')
        assert result == mock_content


@pytest.mark.asyncio
async def test_check_authorization_async():
    connector = SandboxConnector.windows('mock_api_key')
    with patch.object(connector, '_make_request_async', new_callable=AsyncMock,
                      return_value={'data': {'tasks': []}}):
        async with connector:
            result = await connector.check_authorization_async()
        assert result['status'] == 'ok'


@pytest.mark.asyncio
async def test_run_url_analysis_async():
    connector = SandboxConnector.windows('mock_api_key')
    with patch.object(connector, '_make_request_async', new_callable=AsyncMock,
                      return_value={'data': {'taskid': 'task-123'}}):
        async with connector:
            result = await connector.run_url_analysis_async('https://example.com')
        assert result == 'task-123'


@pytest.mark.asyncio
async def test_run_file_analysis_async():
    connector = SandboxConnector.windows('mock_api_key')
    with patch.object(connector, '_make_request_async', new_callable=AsyncMock,
                      return_value={'data': {'taskid': 'task-456'}}):
        async with connector:
            result = await connector.run_file_analysis_async(file_content=b'test', filename='test.txt')
        assert result == 'task-456'


@pytest.mark.asyncio
async def test_get_analysis_report_async_ioc_filters_reputation():
    connector = SandboxConnector.windows('mock_api_key')
    with patch.object(connector, '_make_request_async', new_callable=AsyncMock,
                      return_value=[{'reputation': 2}, {'reputation': 1}]):
        async with connector:
            result = await connector.get_analysis_report_async(
                'task-uuid', report_format='ioc', ioc_reputation='malicious'
            )
        assert len(result) == 1
        assert result[0]['reputation'] == 2


@pytest.mark.asyncio
async def test_linux_run_url_analysis_async():
    from anyrun.connectors import SandboxConnector
    connector = SandboxConnector.linux('mock_api_key')
    with patch.object(connector, '_make_request_async', new_callable=AsyncMock,
                      return_value={'data': {'taskid': 'task-linux'}}):
        async with connector:
            result = await connector.run_url_analysis_async('https://example.com')
        assert result == 'task-linux'


@pytest.mark.asyncio
async def test_android_run_url_analysis_async():
    connector = SandboxConnector.android('mock_api_key')
    with patch.object(connector, '_make_request_async', new_callable=AsyncMock,
                      return_value={'data': {'taskid': 'task-android'}}):
        async with connector:
            result = await connector.run_url_analysis_async('https://example.com')
        assert result == 'task-android'


@pytest.mark.asyncio
async def test_macos_run_url_analysis_async():
    connector = SandboxConnector.macos('mock_api_key')
    with patch.object(connector, '_make_request_async', new_callable=AsyncMock,
                      return_value={'data': {'taskid': 'task-macos'}}):
        async with connector:
            result = await connector.run_url_analysis_async('https://example.com')
        assert result == 'task-macos'


@pytest.mark.asyncio
async def test_windows_run_download_analysis_async():
    connector = SandboxConnector.windows('mock_api_key')
    with patch.object(connector, '_make_request_async', new_callable=AsyncMock,
                      return_value={'data': {'taskid': 'task-download'}}):
        async with connector:
            result = await connector.run_download_analysis_async('https://example.com/file.exe')
        assert result == 'task-download'


@pytest.mark.asyncio
async def test_get_task_status_async_yields_prepared_response():
    connector = SandboxConnector.windows('mock_api_key')
    mock_content = AsyncMock()
    first_chunk = b'data: {"task": {"status": 100, "remaining": "0"}}\n'
    mock_content.readuntil = AsyncMock(side_effect=[first_chunk, b''])
    mock_response = AsyncMock()
    mock_response.content = mock_content
    mock_response.content_type = 'text/event-stream'

    with patch.object(connector, '_make_request_async', new_callable=AsyncMock, return_value=mock_response):
        async with connector:
            chunks = []
            async for chunk in connector.get_task_status_async('task-1', simplify=True):
                chunks.append(chunk)
        assert len(chunks) >= 1
        assert chunks[0].get('status') == 'COMPLETED'


def test_check_authorization_sync():
    connector = SandboxConnector.windows('mock_api_key')
    with patch.object(connector, 'check_authorization_async', new_callable=AsyncMock,
                      return_value={'status': 'ok', 'description': 'ok'}):
        result = connector.check_authorization()
        assert result['status'] == 'ok'


def test_get_analysis_history_sync():
    connector = SandboxConnector.windows('mock_api_key')
    with patch.object(connector, 'get_analysis_history_async', new_callable=AsyncMock,
                      return_value=[{'taskid': '1'}]):
        result = connector.get_analysis_history(team=True, skip=5, limit=10)
        assert result == [{'taskid': '1'}]


def test_get_analysis_report_sync():
    connector = SandboxConnector.windows('mock_api_key')
    with patch.object(connector, 'get_analysis_report_async', new_callable=AsyncMock,
                      return_value={'data': {'analysis': {}}}):
        result = connector.get_analysis_report('task-uuid')
        assert result == {'data': {'analysis': {}}}


def test_add_time_to_task_sync():
    connector = SandboxConnector.windows('mock_api_key')
    with patch.object(connector, 'add_time_to_task_async', new_callable=AsyncMock, return_value={'ok': True}):
        result = connector.add_time_to_task('task-uuid')
        assert result == {'ok': True}


def test_stop_task_sync():
    connector = SandboxConnector.windows('mock_api_key')
    with patch.object(connector, 'stop_task_async', new_callable=AsyncMock, return_value={'ok': True}):
        result = connector.stop_task('task-uuid')
        assert result == {'ok': True}


def test_delete_task_sync():
    connector = SandboxConnector.windows('mock_api_key')
    with patch.object(connector, 'delete_task_async', new_callable=AsyncMock, return_value={'ok': True}):
        result = connector.delete_task('task-uuid')
        assert result == {'ok': True}


def test_get_task_status_sync_iterator():
    connector = SandboxConnector.windows('mock_api_key')
    async def mock_status_gen():
        yield {'status': 'COMPLETED'}
    with patch.object(connector, 'get_task_status_async', return_value=mock_status_gen()):
        items = list(connector.get_task_status('task-uuid', simplify=True))
        assert len(items) >= 1
        assert items[0]['status'] == 'COMPLETED'


def test_get_user_environment_sync():
    connector = SandboxConnector.windows('mock_api_key')
    with patch.object(connector, 'get_user_environment_async', new_callable=AsyncMock, return_value={'data': {}}):
        result = connector.get_user_environment()
        assert result == {'data': {}}


def test_get_user_limits_sync():
    connector = SandboxConnector.windows('mock_api_key')
    with patch.object(connector, 'get_user_limits_async', new_callable=AsyncMock, return_value={'daily': 10}):
        result = connector.get_user_limits()
        assert result == {'daily': 10}


def test_get_user_presets_sync():
    connector = SandboxConnector.windows('mock_api_key')
    with patch.object(connector, 'get_user_presets_async', new_callable=AsyncMock, return_value=[]):
        result = connector.get_user_presets()
        assert result == []


def test_download_pcap_sync():
    connector = SandboxConnector.windows('mock_api_key')
    with patch.object(connector, 'download_pcap_async', new_callable=AsyncMock, return_value=b'pcap'):
        result = connector.download_pcap('task-uuid')
        assert result == b'pcap'


def test_get_analysis_verdict_sync():
    connector = SandboxConnector.windows('mock_api_key')
    with patch.object(connector, 'get_analysis_verdict_async', new_callable=AsyncMock, return_value='Malicious'):
        result = connector.get_analysis_verdict('task-uuid')
        assert result == 'Malicious'


def test_download_file_sample_sync():
    connector = SandboxConnector.windows('mock_api_key')
    with patch.object(connector, 'download_file_sample_async', new_callable=AsyncMock, return_value=b'zip'):
        result = connector.download_file_sample('task-uuid')
        assert result == b'zip'


@pytest.mark.asyncio
async def test_get_analysis_history_async_with_params():
    connector = SandboxConnector.windows('mock_api_key')
    with patch.object(connector, '_make_request_async', new_callable=AsyncMock,
                      return_value={'data': {'tasks': [{'taskid': '1'}, {'taskid': '2'}]}}) as mock_req:
        async with connector:
            result = await connector.get_analysis_history_async(team=True, skip=10, limit=50)
        assert len(result) == 2
        mock_req.assert_called_once()
        call_kwargs = mock_req.call_args
        assert call_kwargs[1]['json']['team'] is True
        assert call_kwargs[1]['json']['skip'] == 10
        assert call_kwargs[1]['json']['limit'] == 50


@pytest.mark.asyncio
async def test_get_analysis_report_async_stix_format():
    connector = SandboxConnector.windows('mock_api_key')
    with patch.object(connector, '_make_request_async', new_callable=AsyncMock,
                      return_value={'objects': []}):
        async with connector:
            result = await connector.get_analysis_report_async('task-uuid', report_format='stix')
        assert result == {'objects': []}


@pytest.mark.asyncio
async def test_get_analysis_report_async_with_filepath_returns_none():
    connector = SandboxConnector.windows('mock_api_key')
    with tempfile.TemporaryDirectory() as tmpdir:
        with patch.object(connector, '_make_request_async', new_callable=AsyncMock,
                          return_value={'data': {}}), \
             patch.object(connector, '_dump_response_content', new_callable=AsyncMock):
            async with connector:
                result = await connector.get_analysis_report_async('task-uuid', filepath=tmpdir)
            assert result is None


@pytest.mark.asyncio
async def test_get_analysis_report_async_html_format():
    connector = SandboxConnector.windows('mock_api_key')
    mock_response = MagicMock()
    mock_response.content_type = 'application/octet-stream'
    mock_response.status = 200
    mock_response.content = b'<html>report</html>'
    with patch.object(connector, '_make_request_async', new_callable=AsyncMock, return_value=mock_response):
        async with connector:
            result = await connector.get_analysis_report_async('task-uuid', report_format='html')
        assert result == '<html>report</html>'


@pytest.mark.asyncio
async def test_read_content_stream_decodes_content():
    connector = SandboxConnector.windows('mock_api_key')
    mock_response = MagicMock()
    mock_response.content_type = 'application/octet-stream'
    mock_response.status = 200
    mock_response.content = b'<html/>'
    result = await connector._read_content_stream(mock_response)
    assert result == '<html/>'


@pytest.mark.asyncio
async def test_read_content_stream_aiohttp_response_path():
    connector = SandboxConnector.windows('mock_api_key')
    mock_response = MagicMock()
    mock_response.content_type = 'application/octet-stream'
    mock_response.status = 200
    mock_response.content.read = AsyncMock(return_value=b'<body/>')
    with patch('anyrun.connectors.sandbox.base_connector.aiohttp.ClientResponse', type(mock_response)):
        result = await connector._read_content_stream(mock_response)
    assert result == '<body/>'


@pytest.mark.asyncio
async def test_download_pcap_async_with_filepath():
    connector = SandboxConnector.windows('mock_api_key')
    mock_response = AsyncMock()
    mock_response.content.read = AsyncMock(return_value=b'pcap data')
    with patch.object(connector, '_make_request_async', new_callable=AsyncMock, return_value=mock_response), \
         tempfile.TemporaryDirectory() as tmpdir:
        async with connector:
            result = await connector.download_pcap_async('task-uuid', filepath=tmpdir)
        assert result is None
        path = os_module.path.join(tmpdir, 'task-uuid_network_traffic_dump.zip')
        assert os_module.path.isfile(path)


@pytest.mark.asyncio
async def test_download_file_sample_async():
    connector = SandboxConnector.windows('mock_api_key')
    report = {
        'analysis': {
            'options': {'privateSample': 'true'},
            'content': {'mainObject': {'type': 'file', 'permanentUrl': 'https://content.any.run/sample.zip'}},
        }
    }
    mock_report_response = {'data': report}
    mock_sample_response = AsyncMock()
    mock_sample_response.content.read = AsyncMock(return_value=b'zip data')
    with patch.object(connector, 'get_analysis_report_async', new_callable=AsyncMock,
                      return_value=mock_report_response), \
         patch.object(connector, '_make_request_async', new_callable=AsyncMock,
                      return_value=mock_sample_response):
        async with connector:
            result = await connector.download_file_sample_async('task-uuid')
        assert result == b'zip data'


@pytest.mark.asyncio
async def test_prepare_iocs_all_returns_all():
    connector = SandboxConnector.windows('mock_api_key')
    iocs = [{'reputation': 0}, {'reputation': 1}, {'reputation': 2}]
    result = await connector._prepare_iocs(iocs, 'all')
    assert len(result) == 3


@pytest.mark.asyncio
async def test_get_task_status_async_skips_meta_lines():
    connector = SandboxConnector.windows('mock_api_key')
    mock_content = AsyncMock()
    mock_content.readuntil = AsyncMock(side_effect=[
        b'\n',
        b'id: 1\n',
        b'data: {"task": {"status": 100, "remaining": "0"}}\n',
        b'',
    ])
    mock_response = AsyncMock()
    mock_response.content = mock_content
    mock_response.content_type = 'text/event-stream'
    with patch.object(connector, '_make_request_async', new_callable=AsyncMock, return_value=mock_response):
        async with connector:
            chunks = []
            async for chunk in connector.get_task_status_async('task-1', simplify=False):
                chunks.append(chunk)
        assert len(chunks) == 1
        assert chunks[0].get('task', {}).get('status') == 100


@pytest.mark.asyncio
async def test_process_dump_writes_file():
    connector = SandboxConnector.windows('mock_api_key')
    with tempfile.TemporaryDirectory() as tmpdir:
        filepath = os_module.path.join(tmpdir, 'out.txt')
        await connector._process_dump(filepath, 'test content', 'w')
        assert os_module.path.isfile(filepath)
        with open(filepath) as f:
            assert f.read() == 'test content'
