import sys

from anyrun.version import __version__


class Config:
    ANY_RUN_API_URL: str = 'https://api.any.run/v1'
    ANY_RUN_CONTENT_URL: str = 'https://content.any.run/tasks'
    ANY_RUN_REPORT_URL: str = 'https://api.any.run/report'

    TAXII_FULL: str = '3dce855a-c044-5d49-9334-533c24678c5a'
    TAXII_IP: str = '55cda200-e261-5908-b910-f0e18909ef3d'
    TAXII_DOMAIN: str = '2e0aa90a-5526-5a43-84ad-3db6f4549a09'
    TAXII_URL: str = '05bfa343-e79f-57ec-8677-3122ca33d352'

    DEFAULT_REQUEST_TIMEOUT_IN_SECONDS: int = 300
    DEFAULT_WAITING_TIMEOUT_IN_SECONDS: int = 3
    PUBLIC_INTEGRATION: str = f'Public:{sys.version.split()[0]}'
    SDK_VERSION: str = f'anyrun_sdk:{__version__}'
