import sys

from anyrun.version import __version__


class Config:
    ANY_RUN_API_URL = 'https://api.any.run/v1'
    ANY_RUN_CONTENT_URL = 'https://content.any.run/tasks'
    ANY_RUN_REPORT_URL = 'https://api.any.run/report'

    TAXII_FULL = '3dce855a-c044-5d49-9334-533c24678c5a'
    TAXII_IP = '55cda200-e261-5908-b910-f0e18909ef3d'
    TAXII_DOMAIN = '2e0aa90a-5526-5a43-84ad-3db6f4549a09'
    TAXII_URL = '05bfa343-e79f-57ec-8677-3122ca33d352'
    TAXII_DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'

    DEFAULT_REQUEST_TIMEOUT_IN_SECONDS = 300
    DEFAULT_WAITING_TIMEOUT_IN_SECONDS = 3
    PUBLIC_INTEGRATION = 'Public:{}'.format(sys.version.split()[0])
    SDK_VERSION = 'anyrun_sdk:{}'.format(__version__)
