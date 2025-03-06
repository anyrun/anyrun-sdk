import asyncio
from typing import Callable, Any, AsyncIterator


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



