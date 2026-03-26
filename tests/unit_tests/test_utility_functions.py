"""Unit tests for anyrun.utils.utility_functions."""

import asyncio
import warnings

import pytest

from anyrun.utils.utility_functions import (
    get_running_loop,
    execute_synchronously,
    deprecated,
)


def test_get_running_loop_returns_loop():
    loop = get_running_loop()
    assert loop is not None
    assert isinstance(loop, asyncio.AbstractEventLoop)


def test_execute_synchronously_runs_async_function():
    async def add(a: int, b: int) -> int:
        return a + b

    result = execute_synchronously(add, 2, 3)
    assert result == 5


def test_execute_synchronously_with_kwargs():
    async def greet(name: str, greeting: str = 'Hello') -> str:
        return f'{greeting}, {name}!'

    result = execute_synchronously(greet, 'World', greeting='Hi')
    assert result == 'Hi, World!'


def test_deprecated_decorator_emits_warning():
    @deprecated('Use new_func instead.')
    def old_func():
        return 42

    with pytest.warns(DeprecationWarning, match='old_func is deprecated'):
        assert old_func() == 42


def test_deprecated_decorator_without_reason():
    @deprecated()
    def legacy():
        return 'ok'

    with pytest.warns(DeprecationWarning, match='legacy is deprecated'):
        assert legacy() == 'ok'


def test_deprecated_preserves_function_name():
    @deprecated()
    def my_function():
        pass

    assert my_function.__name__ == 'my_function'


def test_execute_async_iterator_yields_items():
    from anyrun.utils.utility_functions import execute_async_iterator

    async def simple_async_iterator():
        yield {'a': 1}
        yield {'b': 2}

    gen = execute_async_iterator(simple_async_iterator())
    items = list(gen)
    assert items == [{'a': 1}, {'b': 2}]


def test_get_running_loop_creates_new_loop_on_runtime_error():
    import asyncio
    from unittest.mock import patch
    from anyrun.utils.utility_functions import get_running_loop

    with patch('anyrun.utils.utility_functions.asyncio.get_event_loop') as mock_get:
        mock_get.side_effect = RuntimeError('no running loop')
        loop = get_running_loop()
        assert loop is not None
        assert isinstance(loop, asyncio.AbstractEventLoop)
