"""Unit tests for anyrun.utils.exceptions."""

import pytest

from anyrun.utils.exceptions import RunTimeException


def test_run_time_exception_str_with_code():
    exc = RunTimeException('Test error', code=401)
    assert '[AnyRun Exception]' in str(exc)
    assert '401' in str(exc)
    assert 'Test error' in str(exc)


def test_run_time_exception_str_without_code():
    exc = RunTimeException('No code')
    assert 'unspecified' in str(exc)
    assert 'No code' in str(exc)


def test_run_time_exception_description():
    exc = RunTimeException('Error message', code=500)
    assert exc.description == 'Error message'


def test_run_time_exception_status_code():
    exc = RunTimeException('Error', code=404)
    assert exc.status_code == 404


def test_run_time_exception_status_code_none():
    exc = RunTimeException('Error')
    assert exc.status_code is None


def test_run_time_exception_json():
    exc = RunTimeException('Desc', code=400)
    assert exc.json == {'description': 'Desc', 'code': 400}


def test_run_time_exception_json_without_code():
    exc = RunTimeException('Desc')
    assert exc.json == {'description': 'Desc', 'code': None}
