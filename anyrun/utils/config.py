import sys

from anyrun.version import __version__


class Config:
    ANY_RUN_API_URL: str = 'https://api.any.run/v1'
    ANY_RUN_CONTENT_URL: str = 'https://content.any.run/tasks'
    ANY_RUN_REPORT_URL: str = 'https://api.any.run/report'

    DEFAULT_REQUEST_TIMEOUT_IN_SECONDS: int = 300
    DEFAULT_WAITING_TIMEOUT_IN_SECONDS: int = 3
    PUBLIC_USER_AGENT: str = f'public/{sys.version.split()[0]}'
    SDK_USER_AGENT: str = f'anyrun-sdk/{__version__}'
