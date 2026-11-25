import functools
import hashlib
import sys
import threading
import time
from collections.abc import Awaitable
from http import HTTPStatus
from typing import Any, Callable, Optional

from anyrun.utils.config import Config
from anyrun.utils.exceptions import RunTimeException

# {"<root_url>:<function>:<sha256(api_key)>": monotonic timestamp of the throttle}. Lives only inside the current process.
THROTTLE_STORAGE: dict[str, float] = {}
# Entries that currently have a single "probe" request in flight after their TTL has expired.
_PROBING: set[str] = set()
_LOCK = threading.Lock()


class ThrottledException(RunTimeException):
    """Raised instead of sending a request, if the function is temporarily throttled for the API key and root url."""


def _throttle_id(root_url: str, function: str, api_key: str) -> str:
    return f'{root_url}:{function}:{hashlib.sha256(api_key.encode()).hexdigest()}'


def _obfuscate_key(api_key: str) -> str:
    """Only for logs. The first and the last 5 symbols of the key without its prefix (API-KEY or Basic)."""
    secret = api_key.split()[-1]
    return f'{secret[:5]}..{secret[-5:]}' if len(secret) > 10 else '***'


def _status_of(exception: RunTimeException) -> Optional[int]:
    try:
        return int(exception.status_code) if exception.status_code else None
    except (TypeError, ValueError):
        return None


def is_throttling_error(exception: RunTimeException) -> bool:
    """
    Decides whether the error says that the API key can not be used (license problems or too many requests).
    Feature-specific errors (e.g. "Private content", "Requires an active subscription to a Hunter or Enterprise plan")
    must not cause a throttle, because the same function may still work with other arguments.
    """
    status = _status_of(exception)
    message = (exception.description or '').lower()

    if status == HTTPStatus.TOO_MANY_REQUESTS:
        return not any(ignored in message for ignored in Config.THROTTLE_IGNORED_429_MESSAGES)

    if status == HTTPStatus.UNAUTHORIZED:
        return True

    if status == HTTPStatus.FORBIDDEN:
        return any(license_message in message for license_message in Config.THROTTLE_LICENSE_ERROR_MESSAGES)

    return False


def _acquire(throttle_id: str, function: str, root_url: str) -> bool:
    """
    Raises ThrottledException if the entry is throttled.

    :return: True if the caller became the probe request (the TTL has expired), False for a regular request
    """
    with _LOCK:
        throttled_at = THROTTLE_STORAGE.get(throttle_id)
        if throttled_at is None:
            return False

        remaining = Config.THROTTLE_TTL_IN_SECONDS - (time.monotonic() - throttled_at)
        if remaining > 0:
            raise ThrottledException(
                f'Requests of {function} to {root_url} with this API key are throttled for {int(remaining) + 1} more seconds '
                f'because of a previous license-related error. The request was not sent',
                HTTPStatus.TOO_MANY_REQUESTS,
            )

        if throttle_id in _PROBING:
            raise ThrottledException(
                f'Requests of {function} to {root_url} with this API key are throttled until the verification request is finished. '
                f'The request was not sent',
                HTTPStatus.TOO_MANY_REQUESTS,
            )

        _PROBING.add(throttle_id)
        return True


def _throttle(throttle_id: str, function: str, root_url: str, api_key: str, exception: RunTimeException) -> None:
    with _LOCK:
        THROTTLE_STORAGE[throttle_id] = time.monotonic()
        _PROBING.discard(throttle_id)

    print(
        f'{function} to {root_url} is throttled for API key {_obfuscate_key(api_key)}'
        f' for {Config.THROTTLE_TTL_IN_SECONDS} seconds: {exception.description}',
    )


def _release_probe(throttle_id: str, unban: bool) -> None:
    with _LOCK:
        _PROBING.discard(throttle_id)
        if unban:
            THROTTLE_STORAGE.pop(throttle_id, None)


async def _raise_for_error_status(response: Any, enable_requests: bool) -> None:
    """
    Requests made with parse_response=False return the response as is, so its status is checked here.

    :raises RunTimeException: If the response has an error status
    """
    status = response.status_code if enable_requests else response.status
    if status < HTTPStatus.BAD_REQUEST:
        return

    try:
        body = response.json() if enable_requests else await response.json(content_type=None)
        description = body.get('message') or body.get('description')
    except Exception:  # The body is not a json document. The status is still enough to report the error
        description = None

    raise RunTimeException(description or 'An unspecified error occurred', status)


def throttle_requests(func: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
    """
    Decorator for AnyRunConnector._make_request_async. If Config.ENABLE_THROTTLING is True and a request gets
    a license-related or "too many requests" error, stops sending requests of the same calling function with the same
    API key and root url for Config.THROTTLE_TTL_IN_SECONDS. Other functions and root urls keep working, so e.g.
    a missing TI license does not block the Sandbox. After the TTL exactly one request is let through to verify the key:
    if it succeeds the throttle is removed, if it fails with the same kind of error the function is throttled again.

    While throttling is enabled, requests made with parse_response=False raise RunTimeException on an error status
    too, instead of returning the error response.
    """

    @functools.wraps(func)
    async def wrapper(self, *args: Any, **kwargs: Any) -> Any:
        if not Config.ENABLE_THROTTLING or not self._api_key:
            return await func(self, *args, **kwargs)

        # The frame which awaits the request. Must be read before the first await
        caller = sys._getframe(1)  # noqa: SLF001
        if caller.f_code.co_name == 'check_proxy_async':
            # The proxy check does not call the ANY.RUN API, so its answer says nothing about the API key
            return await func(self, *args, **kwargs)

        function = f'{caller.f_globals.get("__name__")}'
        root_url = str(self._root_url).lower()
        throttle_id = _throttle_id(root_url, function, self._api_key)

        is_probe = _acquire(throttle_id, function, root_url)

        try:
            result = await func(self, *args, **kwargs)
            if not kwargs.get('parse_response', True):
                await _raise_for_error_status(result, self._enable_requests)
        except RunTimeException as exception:
            if is_throttling_error(exception):
                _throttle(throttle_id, function, root_url, self._api_key, exception)
            elif is_probe:
                # An HTTP answer without a license problem means the key works. No status means a connection problem
                # (nothing is known about the key), so the throttle stays and the next request will probe again.
                _release_probe(throttle_id, unban=_status_of(exception) is not None)
            raise
        except BaseException:
            if is_probe:
                _release_probe(throttle_id, unban=False)
            raise

        if is_probe:
            _release_probe(throttle_id, unban=True)
        return result

    return wrapper
