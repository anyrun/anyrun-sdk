import sys

from anyrun.version import __version__


class Config:
    ANY_RUN_API_URL: str = 'https://api.any.run/v1'

    DEFAULT_REQUEST_TIMEOUT_IN_SECONDS: int = 300
    DEFAULT_WAITING_TIMEOUT_IN_SECONDS: int = 3
    PUBLIC_USER_AGENT: str = f'public/{sys.version.split()[0]}'
    SDK_USER_AGENT: str = f'anyrun-sdk/{__version__}'
