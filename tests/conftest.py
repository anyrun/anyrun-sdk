import pytest
from typing import List

@pytest.fixture(scope='function')
def query_params_config() -> dict:
    params = {
                'ip': 'true',
                'url': 'true',
                'domain': 'true',
                'file': 'true',
                'port': 'true',
                'show_revoked': 'false',
                'get_new_ioc': 'false',
                'period': 'day',
                'date_from': 1710381199,
                'date_to': 1740381199,
                'limit': 100,
             }

    yield params
    del params


class MockFeedsConnector:
    async def get_stix_async(self, page: int = 1, **kwargs) -> list:
        return await self._stix_response() if page <= 1 else await self._empty_response()

    async def get_misp_async(self, page: int = 1, **kwargs) -> list:
        return await self._misp_response() if page <= 1 else await self._empty_response()

    async def get_network_iocs_async(self, page: int = 1, **kwargs) -> list:
        return await self._misp_response() if page <= 1 else await self._empty_response()

    @staticmethod
    async def _empty_response():
        return []

    @staticmethod
    async def _stix_response() -> List[dict]:
        return [
            {"type": "url", "id": "url--c955128d-e822-5121-b2dd-68a7061a13"},
            {"type": "url", "id": "url--c955128d-e822-5121-b2dd-68a7061a12"},
            {"type": "url", "id": "url--c955128d-e822-5121-b2dd-68a7061a11"}
        ]

    @staticmethod
    async def _misp_response() -> List[dict]:
        return [
            {"Event": {"uuid": "ba910tdb-f5f3-554f-787b-8cca47f39faa"}},
            {"Event": {"uuid": "ba910tdb-f5f3-554f-787b-8cca47f39fab"}},
            {"Event": {"uuid": "ba910tdb-f5f3-554f-787b-8cca47f39fac"}}
        ]

    @staticmethod
    async def _network_iocs_response() -> List[dict]:
        return [
            {"IOC": "176.106.101.98"},
            {"IOC": "175.106.101.98"},
            {"IOC": "174.106.101.98"}
        ]

class MockAiohttpClientResponse:
    def __init__(self, content_type: str):
        self.content_type = content_type
        self.status = 401

    def __str__(self) -> str:
        return 'Error message'

