import sys

from anyrun.version import __version__


class Config:
    ANY_RUN_API_URL: str = 'https://api.{root_url}/v1'
    ANY_RUN_CONTENT_URL: str = 'https://content.{root_url}/tasks'
    ANY_RUN_REPORT_URL: str = 'https://api.{root_url}/report'
    ANY_RUN_APP_URL: str = 'https://app.{root_url}'

    TAXII_FULL: str = '3dce855a-c044-5d49-9334-533c24678c5a'
    TAXII_IP: str = '55cda200-e261-5908-b910-f0e18909ef3d'
    TAXII_DOMAIN: str = '2e0aa90a-5526-5a43-84ad-3db6f4549a09'
    TAXII_URL: str = '05bfa343-e79f-57ec-8677-3122ca33d352'
    TAXII_DATE_FORMAT: str = '%Y-%m-%dT%H:%M:%S.%fZ'

    DEFAULT_REQUEST_TIMEOUT_IN_SECONDS: int = 300
    DEFAULT_WAITING_TIMEOUT_IN_SECONDS: int = 3
    DEFAULT_ROOT_URL: str = 'any.run'
    PUBLIC_INTEGRATION: str = f'Public:{sys.version.split()[0]}'
    SDK_VERSION: str = f'anyrun_sdk:{__version__}'

    ENABLE_THROTTLING: bool = False
    THROTTLE_TTL_IN_SECONDS: int = 1800
    # 429 messages (lowercase substrings) that must not cause a throttle: a parallel task limit is fine to retry
    # right away, an AI summary limit concerns only AI reports
    THROTTLE_IGNORED_429_MESSAGES: tuple[str, ...] = ('parallel task limit', 'ai summary limit exceeded')
    THROTTLE_LICENSE_ERROR_MESSAGES: tuple[str, ...] = (
        'authorization required',
        'wrong authorization data',
        "can't recognize you",
        'api is not available on the free plan',
        'api is disabled in your account',
    )
