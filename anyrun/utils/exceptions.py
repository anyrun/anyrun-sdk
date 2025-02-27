from typing import Optional


class RunTimeException(Exception):
    def __init__(self, reason: dict) -> None:
        self._reason = reason

    def __str__(self) -> str:
        return (
            f'[AnyRun Exception] '
            f'Status: {self._reason.get("status")}. '
            f'Status code: {int(self._reason.get("code")) if self._reason.get("code") else "unspecified"}. '
            f'Description: {self._reason.get("description")}'
        )

    @property
    def json(self) -> dict:
        return self._reason

    @property
    def status(self) -> str:
        return self._reason.get('status')

    @property
    def status_code(self) -> Optional[str]:
        return self._reason.get('code')

    @property
    def description(self) -> str:
        return self._reason.get('description')
