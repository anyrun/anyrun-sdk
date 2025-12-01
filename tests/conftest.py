import pytest


@pytest.fixture(scope='function')
def query_params_config() -> dict:
    params = {
                'match[revoked]': False
             }

    yield params
    del params


class MockAiohttpClientResponse:
    def __init__(self, content_type: str):
        self.content_type = content_type
        self.status = 401

    def __str__(self) -> str:
        return 'Error message'

