import asyncio
import inspect
import warnings
import functools
from typing import Callable, Any, AsyncIterator

from anyrun import RunTimeException


def execute_async_iterator(async_iterator: AsyncIterator[dict]) -> Any:
    """ Provides an async iterator management for the synchronous code """
    event_loop = get_running_loop()

    while True:
        try:
            yield event_loop.run_until_complete(async_iterator.__anext__())
        except StopAsyncIteration:
            break


def execute_synchronously(function: Callable, *args, **kwargs) -> Any:
    """ Creates a coroutine function using the given parameters and then executes it in the event loop """
    event_loop = get_running_loop()
    return event_loop.run_until_complete(function(*args, **kwargs))


def get_running_loop() -> asyncio.AbstractEventLoop:
    """ Tries to get a running event loop. If not found, creates a new one and returns it """
    try:
        return asyncio.get_event_loop()
    except RuntimeError:
        event_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(event_loop)
        return event_loop


def drop_empty_values(params: dict) -> dict:
    """ Returns a copy of params without None and empty values. Boolean values (including False) are kept """
    return {key: value for key, value in params.items() if value or value in (True, False)}


def check_if_analysis_initialized(func):
    """
    Checks if taskid in Sandbox API response JSON.

    If the task was queued, returns queueTaskId when the decorated function was called with the enabled
    **queue_parallel** option, otherwise raises an exception
    """
    signature = inspect.signature(func)

    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        params = await func(*args, **kwargs)

        if params is None:
            raise RunTimeException('Analysis is not started.', 500)

        if 'queueTaskId' in params.get('data'):
            queue_task_id = params.get('data').get('queueTaskId')

            if is_queue_parallel_enabled(signature, args, kwargs):
                return queue_task_id

            raise RunTimeException(f'Analysis is not started. Queue ID: {queue_task_id}', 500)

        return params.get('data').get('taskid')

    return wrapper


def is_queue_parallel_enabled(signature: inspect.Signature, args: tuple, kwargs: dict) -> bool:
    """ Reads the **queue_parallel** option from the call arguments, no matter if it was passed positionally or by keyword """
    bound_arguments = signature.bind(*args, **kwargs)
    bound_arguments.apply_defaults()
    return bool(bound_arguments.arguments.get('queue_parallel', False))


def deprecated(reason: str = ""):
    def decorator(func):
        message = f"{func.__name__} is deprecated."
        if reason:
            message += f" {reason}"

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            warnings.warn(message, DeprecationWarning, stacklevel=2)
            return func(*args, **kwargs)
        return wrapper
    return decorator
