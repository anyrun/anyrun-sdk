"""
Regression tests for file submissions in the enable_requests mode.

The requests package silently drops `json` when `files` are sent, so the analysis options must be
sent as multipart form fields. These tests stub requests.Session.send so the real requests body
encoding runs and the test checks what actually goes over the wire.
"""
import pytest

from anyrun.utils.utility_functions import drop_empty_values
from tests.unit_tests.core.sandbox.wire_helpers import OS_CONNECTORS, SCOPES, send_with_aiohttp, send_with_requests


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
@pytest.mark.parametrize('extra', [{}, {'queue_parallel': True}])
def test_requests_and_aiohttp_file_uploads_send_the_same_fields(os_name, scope, extra):
    kwargs = {'file_content': b'abc', 'filename': 'a.txt', 'user_tags': 'tag', 'opt_timeout': 30, **extra}

    requests_fields = send_with_requests(OS_CONNECTORS[os_name]('key', enable_requests=True, **scope), **kwargs)
    aiohttp_fields = send_with_aiohttp(OS_CONNECTORS[os_name]('key', **scope), **kwargs)

    assert set(requests_fields) == set(aiohttp_fields)


def test_drop_empty_values_keeps_booleans_and_zero_but_drops_none_and_empty_strings():
    params = {'none': None, 'empty': '', 'false': False, 'true': True, 'zero': 0, 'value': 'x'}

    assert drop_empty_values(params) == {'false': False, 'true': True, 'zero': 0, 'value': 'x'}
    assert params['none'] is None
