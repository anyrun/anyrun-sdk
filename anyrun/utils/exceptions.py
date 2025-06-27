from typing import Optional, Union


class RunTimeException(Exception):
    def __init__(self, description: str, code: Optional[Union[str, int]] = None) -> None:
        self._description = description
        self._code = code

    def __str__(self) -> str:
        return (
            '[AnyRun Exception] '
            'Status code: {}. '.format(int(self._code) if self._code else "unspecified") +
            'Description: {}.'.format(self._description)
        )

    @property
    def json(self) -> dict:
        return {
                'description': self._description,
                'code': self._code,
            }

    @property
    def status_code(self) -> Optional[str]:
        return self._code

    @property
    def description(self) -> str:
        return self._description
