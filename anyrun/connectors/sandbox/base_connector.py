import os
import json
from uuid import UUID
from typing import Optional, Union, BinaryIO, AsyncIterator, Iterator

import aiohttp
import aiofiles

from anyrun.connectors.base_connector import AnyRunConnector
from anyrun.utils.config import Config
from anyrun.utils.exceptions import RunTimeException
from anyrun.utils.utility_functions import execute_synchronously, execute_async_iterator


class BaseSandBoxConnector(AnyRunConnector):
    """
    Provides ANY.RUN TI Yara Lookup endpoints management.
    Uses aiohttp library for the asynchronous calls
    """
    def __init__(
            self,
            api_key: str,
            user_agent: str = Config.PUBLIC_USER_AGENT,
            trust_env: bool = False,
            verify_ssl: bool = False,
            proxy: Optional[str] = None,
            proxy_auth: Optional[str] = None,
            connector: Optional[aiohttp.BaseConnector] = None,
            timeout: int = Config.DEFAULT_REQUEST_TIMEOUT_IN_SECONDS
    ) -> None:
        """
        :param api_key: ANY.RUN API Key in format: API-KEY <api_key> or Basic <base64_auth>
        :param user_agent: User-Agent header value
        :param trust_env: Trust environment settings for proxy configuration
        :param verify_ssl: Perform SSL certificate validation for HTTPS requests
        :param proxy: Proxy url
        :param proxy_auth: Proxy authorization url
        :param connector: A custom aiohttp connector
        :param timeout: Override the session’s timeout
        """
        super().__init__(
            api_key,
            user_agent,
            trust_env,
            verify_ssl,
            proxy,
            proxy_auth,
            connector,
            timeout
        )

    def get_analysis_history(
            self,
            team: bool = False,
            skip: int = 0,
            limit: int = 25
    ) -> list[Optional[dict]]:
        """
        Returns last tasks from the user's history and their basic information

        :param team: Leave this field blank to get your history or specify to get team history
        :param skip: Skip the specified number of tasks
        :param limit: Specify the number of tasks in the result set (not more than 100).
        :return: The list of tasks
        """
        return execute_synchronously(self.get_analysis_history_async, team, skip, limit)

    async def get_analysis_history_async(
            self,
            team: bool = False,
            skip: int = 0,
            limit: int = 25
    ) -> list[Optional[dict]]:
        """
        Returns last tasks from the user's history and their basic information

        :param team: Leave this field blank to get your history or specify to get team history
        :param skip: Skip the specified number of tasks
        :param limit: Specify the number of tasks in the result set (not more than 100).
        :return: The list of tasks
        """
        url = f'{Config.ANY_RUN_API_URL}/analysis'
        body = {
            'team': team,
            'skip': skip,
            'limit': limit
        }

        response_data = await self._make_request_async('GET', url, json=body)
        return response_data.get('data').get('tasks')

    def get_analysis_report(
            self,
            task_uuid: Union[UUID, str],
            report_format: str = 'summary',
            filepath: Optional[str] = None
    ) -> Union[dict, list[dict], str]:
        """
        Returns a submission analysis report by task ID.
        If **filepath** option is specified, dumps report to the file instead

        :param task_uuid: Task uuid
        :param report_format: Supports summary, html, stix, misp, ioc
        :param filepath: Path to file
        :return: Complete report in **json** format
        """
        return execute_synchronously(self.get_analysis_report_async, task_uuid, report_format, filepath)


    async def get_analysis_report_async(
            self,
            task_uuid: Union[UUID, str],
            report_format: str = 'summary',
            filepath: Optional[str] = None
    ) -> Union[dict, list[dict], str, None]:
        """
        Returns a submission analysis report by task ID.
        If **filepath** option is specified, dumps report to the file instead

        :param task_uuid: Task uuid
        :param report_format: Supports summary, html, stix, misp, ioc
        :param filepath: Path to file
        :return: Complete report
        """
        if report_format == 'summary':
            url = f'{Config.ANY_RUN_API_URL}/analysis/{task_uuid}'
            response_data = await self._make_request_async('GET', url)
        elif report_format == 'ioc':
            url = f'{Config.ANY_RUN_REPORT_URL}/{task_uuid}/ioc/json'
            response_data = await self._make_request_async('GET', url)
        elif report_format == 'html':
            url = f'{Config.ANY_RUN_REPORT_URL}/{task_uuid}/summary/html'
            response = await self._make_request_async('GET', url, parse_response=False)
            response_data = await self._read_content_stream(response)
        else:
            url = f'{Config.ANY_RUN_REPORT_URL}/{task_uuid}/summary/{report_format}'
            response_data = await self._make_request_async('GET', url)

        if filepath:
            await self._dump_response_content(response_data, filepath, task_uuid, report_format)
            return

        return response_data

    def add_time_to_task(self, task_uuid: Union[UUID, str]) -> dict:
        """
        Adds 60 seconds of execution time to an active task. The task must belong to the current user

        :param task_uuid: Task uuid
        :return: API response json
        """
        return execute_synchronously(self.add_time_to_task_async, task_uuid)

    async def add_time_to_task_async(self, task_uuid: Union[UUID, str]) -> dict:
        """
        Adds 60 seconds of execution time to an active task. The task must belong to the current user

        :param task_uuid: Task uuid
        :return: API response json
        """
        url = f'{Config.ANY_RUN_API_URL}/analysis/addtime/{task_uuid}'
        return await self._make_request_async('PATCH', url)

    def stop_task(self, task_uuid: Union[UUID, str]) -> dict:
        """
        Stops running task. The task must belong to the current user

        :param task_uuid: Task uuid
        :return: API response json
        """
        return execute_synchronously(self.stop_task_async, task_uuid)

    async def stop_task_async(self, task_uuid: Union[UUID, str]) -> dict:
        """
        Stops running task. The task must belong to the current user

        :param task_uuid: Task uuid
        :return: API response json
        """
        url = f'{Config.ANY_RUN_API_URL}/analysis/stop/{task_uuid}'
        return await self._make_request_async('PATCH', url)

    def delete_task(self, task_uuid: Union[UUID, str]) -> dict:
        """
        Deletes running task. The task must belong to the current user

        :param task_uuid: Task uuid
        :return: API response json
        """
        return execute_synchronously(self.delete_task_async, task_uuid)

    async def delete_task_async(self, task_uuid: Union[UUID, str]) -> dict:
        """
        Deletes running task. The task must belong to the current user

        :param task_uuid: Task uuid
        :return: API response json
        """
        url = f'{Config.ANY_RUN_API_URL}/analysis/delete/{task_uuid}'
        return await self._make_request_async('DELETE', url)

    def get_task_status(self, task_uuid: Union[UUID, str], simplify: bool = True) -> Iterator[dict]:
        """
        Information about the task status is sent to the event stream.
        Returns a synchronous iterator to process the actual status until the task is completed.

        :param task_uuid: Task uuid
        :param simplify: If enabled, returns a simplified dict with the remaining scan time and the current task status
            else returns the entire response
        """
        return execute_async_iterator(self.get_task_status_async(task_uuid, simplify))

    async def get_task_status_async(self, task_uuid: Union[UUID, str], simplify: bool = True) -> AsyncIterator[dict]:
        """
        Information about the task status is sent to the event stream.
        Returns an asynchronous iterator to process the actual status until the task is completed.

        :param task_uuid: Task uuid
        :param simplify: Returns a simplified dict with the remaining scan time and the current task status
        """
        url = f'{Config.ANY_RUN_API_URL}/analysis/monitor/{task_uuid}'
        response_data = await self._make_request_async('GET', url, parse_response=False)

        await self._check_response_content_type(response_data)

        while True:
            # Read the next chunk from the event stream
            chunk = await response_data.content.readuntil(b'\n')
            # Skip the end of chunk and any meta information
            # https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events/Using_server-sent_events#fields
            if chunk == b'\n' or any(chunk.startswith(prefix) for prefix in [b"id", b"event", b"entry"]):
                continue
            # Stop interation if event stream is closed
            elif not chunk:
                break
            # Decode and yield the next chunk
            yield await self._prepare_response(chunk, simplify)

    def get_user_environment(self) -> dict:
        """
        Request available user's environment

        :return: API response json
        """
        return execute_synchronously(self.get_user_environment_async)

    async def get_user_environment_async(self) -> dict:
        """
        Request available user's environment

        :return: API response json
        """
        url = f'{Config.ANY_RUN_API_URL}/environment'
        return await self._make_request_async('GET', url)

    def get_user_limits(self) -> dict:
        """
        Request user's API limits

        :return: API response json
        """
        return execute_synchronously(self.get_user_limits_async)

    async def get_user_limits_async(self) -> dict:
        """
        Request available user's environment

        :return: API response json
        """
        url = f'{Config.ANY_RUN_API_URL}/user'
        return await self._make_request_async('GET', url)

    def get_user_presets(self) -> list[dict]:
        """
        Request user's presets

        :return: API response json
        """
        return execute_synchronously(self.get_user_presets_async)

    async def get_user_presets_async(self) -> list[dict]:
        """
        Request user's presets

        :return: API response json
        """
        url = f'{Config.ANY_RUN_API_URL}/user/presets'
        return await self._make_request_async('GET', url)

    def download_pcap(
            self,
            task_uuid: Union[UUID, str],
            filepath: Optional[str] = None
    ) -> Optional[bytes]:
        """
        Returns a dump of network traffic obtained during the analysis.
        If **filepath** option is specified, dumps traffic to the file instead

        :param task_uuid: Task uuid
        :param filepath: Path to file
        :return: Network traffic bytes
        """
        return execute_synchronously(self.download_pcap_async, task_uuid, filepath)

    async def download_pcap_async(
            self,
            task_uuid: Union[UUID, str],
            filepath: Optional[str] = None
    ) -> Optional[bytes]:
        """
        Returns a dump of network traffic obtained during the analysis.
        If **filepath** option is specified, dumps traffic to the file instead

        :param task_uuid: Task uuid
        :param filepath: Path to file
        :return: Network traffic bytes
        """
        pcap_data = b''
        url = f'{Config.ANY_RUN_CONTENT_URL}/{task_uuid}/download/pcap'

        response_data = await self._make_request_async('GET', url, parse_response=False)

        while True:
            # Read the next chunk from the event stream
            chunk = await response_data.content.readuntil(b'\n')
            # Skip the end of chunk and any meta information
            # https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events/Using_server-sent_events#fields
            if chunk == b'\n' or any(chunk.startswith(prefix) for prefix in [b"id", b"event", b"entry"]):
                continue
            # Stop interation if event stream is closed
            elif not chunk:
                break

            pcap_data += chunk

        if filepath:
            await self._dump_response_content(pcap_data, filepath, task_uuid, 'binary')
            return

        return pcap_data

    async def _generate_multipart_request_body(
            self,
            file: Union[str, BinaryIO],
            **params,
    ) -> aiohttp.MultipartWriter:
        """
        Generates request body for the **form-data** content type

        :param file: Path to file or bytes
        :param params: Dictionary with task settings
        :return: Request payload stored in aiohttp MultipartWriter object instance
        """
        form_data = aiohttp.MultipartWriter("form-data")

        # Prepare file payload
        file_data = await self._get_file_payload(file)
        filename = f'{os.path.basename(file) if isinstance(file, str) else "sdk_file_analysis"}'
        disposition = f'form-data; name="file"; filename="{filename}"'
        file_data.headers["Content-Disposition"] = disposition
        form_data.append_payload(file_data)

        # Choose a task type
        params = await self._set_task_object_type(params, 'file')

        # Prepare analysis settings payload
        for param, value in params.items():
            if value:
                part = form_data.append(str(value))
                part.set_content_disposition('form-data', name=param)

        return form_data

    async def _generate_request_body(
            self,
            object_type: str,
            **params,
        ) -> dict[str, Union[int, str, bool]]:
        """
         Generates request body for the **application/json** content type

        :param object_type: Sandbox object type
        :param params: Dictionary with task settings
        :return: Request payload stored in dictionary
        """
        request_body = {param: value for param, value in params.items() if value}
        return await self._set_task_object_type(request_body, object_type)

    async def _prepare_response(self, chunk: bytes, simplify: bool) -> dict:
        """
        Deserialize response bytes to dictionary

        :param chunk: Current content chunk
        :param simplify: Returns a simplified dict with the remaining scan time and the current task status
        :return: API response json
        """
        # Exclude 'data: ' field from the chunk and decode entire dictionary
        status_data = json.loads(chunk[6:].decode())

        if simplify:
            return {
                'status': await self._resolve_task_status(status_data.get('task').get('status')),
                'seconds_remaining': status_data.get('task').get('remaining')
            }
        return status_data

    async def _read_content_stream(self, response_data: aiohttp.ClientResponse) -> Union[bytes, dict, str]:
        """
        Receives the first fragment of the stream and decodes it

        :param response_data: ClientRepose object
        :return: Decoded content
        """
        await self._check_response_content_type(response_data)

        chunk = await response_data.content.read()
        return chunk.decode()

    async def _dump_response_content(
            self,
            content: Union[dict, bytes, str],
            filepath: str,
            task_uuid: str,
            content_type: str,
    ) -> None:
        """
        Saves response_data to the file according to content type and filepath

        :param content: Response data
        :param filepath: File path
        :param task_uuid: Task UUID
        :param content_type: Response data content type. Supports binary, html.
            Any other formats will be recognized as json
        """
        if content_type == 'binary':
            await self._process_dump(f'{os.path.abspath(filepath)}/{task_uuid}_traffic', content, 'wb')
        elif content_type == 'html':
            await self._process_dump(f'{os.path.abspath(filepath)}/{task_uuid}_report.html', content, 'w')
        else:
            await self._process_dump(
                f'{os.path.abspath(filepath)}/{task_uuid}_report_{content_type}.json', json.dumps(content), 'w'
            )


    @staticmethod
    async def _check_response_content_type(response: aiohttp.ClientResponse) -> None:
        """
        Checks if the response has a **stream-like** content-type


        :param response: API response
        :raises RunTimeException: If response has a different content-type
        """
        if not response.content_type.startswith(('text/event-stream', 'application/octet-stream')):
            if response.content_type.startswith('application/json'):
                raise RunTimeException(
                    {
                        'status': 'error',
                        'code': response.status,
                        'description': (await response.json()).get('message')
                    }
                )
            raise RunTimeException(
                {
                    'status': 'error',
                    'code': response.status,
                    'description': 'An unspecified error occurred while reading the stream'

                }
            )

    @staticmethod
    async def _resolve_task_status(status_code: int) -> str:
        """ Converts an integer status code value to a string representation """
        if status_code == -1:
            return 'FAILED'
        elif 50 <= status_code <= 99:
            return 'RUNNING'
        elif status_code == 100:
            return 'COMPLETED'
        return 'PREPARING'

    @staticmethod
    async def _get_file_payload(file: Union[str, bytes]) -> aiohttp.Payload:
        """
        Generates file payload from received file content. Tries to open a file if given a file path

        :param file: Path to file or bytes
        :return: Aiohttp Payload object instance
        :raises RunTimeException: If invalid filepath is received
        """
        if isinstance(file, bytes):
            return aiohttp.get_payload(file)

        if not os.path.isfile(file):
            raise RunTimeException(
                {
                    'status': 'error',
                    'description': f'Received not valid filepath: {file}'
                }
            )

        async with aiofiles.open(file, mode='rb') as file:
            return aiohttp.get_payload(await file.read())

    @staticmethod
    async def _set_task_object_type(
            params: dict[str, Union[int, str, bool]],
            obj_type: str
    ) -> dict[str, Union[int, str, bool]]:
        """
        Sets **obj_type** value to 'rerun' if **task_rerun_uuid** parameter is not None.
        Otherwise, sets received object type

        :param params: Dictionary with task settings
        :param obj_type: Sandbox task object type
        :return: Dictionary with task settings
        """
        if params.get('task_rerun_uuid'):
            params['obj_type'] = 'rerun'
        else:
            params['obj_type'] = obj_type
        return params

    @staticmethod
    async def _process_dump(filepath: str, content: Union[dict, bytes, str], mode: str) -> None:
        """
        Saves response_data to the file

        :param filepath: File path
        :param content: Response data content
        :param mode: Way to interact with a file for aiofiles library.
            Similar to the build-in open() function mode
        :return:
        """
        async with aiofiles.open(filepath, mode) as file:
            await file.write(content)

