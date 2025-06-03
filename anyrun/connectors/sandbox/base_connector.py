import os
import json
from http import HTTPStatus
from uuid import UUID
from typing import Optional, Union, BinaryIO, AsyncIterator, Iterator

import aiohttp
import aiofiles

from anyrun.connectors.base_connector import AnyRunConnector
from anyrun.utils.config import Config
from anyrun.utils.exceptions import RunTimeException
from anyrun.utils.utility_functions import execute_synchronously, execute_async_iterator


class BaseSandboxConnector(AnyRunConnector):
    """
    Provides ANY.RUN TI Yara Lookup endpoints management.
    Uses aiohttp library for the asynchronous calls
    """
    def __init__(
            self,
            api_key: str,
            integration: str = Config.PUBLIC_INTEGRATION,
            trust_env: bool = False,
            verify_ssl: Optional[str] = None,
            proxy: Optional[str] = None,
            connector: Optional[aiohttp.BaseConnector] = None,
            timeout: int = Config.DEFAULT_REQUEST_TIMEOUT_IN_SECONDS,
            enable_requests: bool = False
    ) -> None:
        """
        :param api_key: ANY.RUN API Key in format: API-KEY <api_key> or Basic <base64_auth>
        :param integration: Name of the integration
        :param trust_env: Trust environment settings for proxy configuration
        :param verify_ssl: Path to SSL certificate
        :param proxy: Proxy url. Example: http://<user>:<pass>@<proxy>:<port>
        :param connector: A custom aiohttp connector
        :param timeout: Override the session’s timeout
        """
        super().__init__(
            api_key,
            integration,
            trust_env,
            verify_ssl,
            proxy,
            connector,
            timeout,
            enable_requests
        )

    def check_authorization(self) -> dict:
        """
        Makes a request to check the validity of the API key.
        The request does not consume the license

        return: Verification status
        """
        return execute_synchronously(self.check_authorization_async)

    async def check_authorization_async(self) -> dict:
        """
        Makes a request to check the validity of the API key.
        The request does not consume the license

        return: Verification status
        """
        await self.get_analysis_history_async()
        return {'status': 'ok', 'description': 'Successful credential verification'}

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
        Deletes task from the history. The task must belong to the current user

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
            yield await self._prepare_response(chunk, simplify, task_uuid)

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
        return (await self._make_request_async('GET', url)).get('data').get('limits')

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
        url = f'{Config.ANY_RUN_CONTENT_URL}/{task_uuid}/download/pcap'
        return await self._download_sample(url, 'pcap', task_uuid, filepath)

    def get_analysis_verdict(self, task_uuid: Union[UUID, str]) -> str:
        """
        Returns a threat level text. Possible values:

        * No threats detected
        * Suspicious activity
        * Malicious activity

        :param task_uuid: Task uuid
        :return: Threat level text
        """
        return execute_synchronously(self.get_analysis_verdict_async, task_uuid)

    async def get_analysis_verdict_async(self, task_uuid: Union[UUID, str]) -> str:
        """
        Returns a threat level text. Possible values:

        * No threats detected
        * Suspicious activity
        * Malicious activity

        :param task_uuid: Task uuid
        :return: Threat level text
        """
        report = await self.get_analysis_report_async(task_uuid, report_format='summary')
        return report.get('data').get('analysis').get('scores').get('verdict').get('threatLevelText')

    def download_file_sample(
            self,
            task_uuid: Union[UUID, str],
            filepath: Optional[str] = None
    ) -> Optional[bytes]:
        """
        Returns a file sample data inside the **zip** archive.
        If **filepath** option is specified, dumps file sample to the zip archive instead.
        The archive password is: infected

        :param task_uuid: Task uuid
        :param filepath: Path to file
        :return: Network traffic bytes
        """
        return execute_synchronously(self.download_file_sample_async, task_uuid, filepath)

    async def download_file_sample_async(
            self,
            task_uuid: Union[UUID, str],
            filepath: Optional[str] = None
    ) -> Optional[bytes]:
        """
        Returns a file sample data inside the **zip** archive.
        If **filepath** option is specified, dumps file sample to the zip archive instead.
        The archive password is: infected

        :param task_uuid: Task uuid
        :param filepath: Path to file
        :return: Network traffic bytes
        """
        report = await self.get_analysis_report_async(task_uuid, report_format='summary')
        url = await self._extract_sample_url(report.get('data'))

        return await self._download_sample(url, 'zip', task_uuid, filepath)

    async def _generate_multipart_request_body(
            self,
            file_content: Optional[bytes] = None,
            filename: Optional[str] = None,
            filepath: Optional[str] = None,
            **params,
    ) -> aiohttp.MultipartWriter:
        """
        Generates request body for the **form-data** content type

        :param file_content: File bytes to analyse.
        :param filename: Filename with file extension.
        :param filepath: Absolute path to file. If specified, automatically process file content and filename
        :param params: Dictionary with task settings
        :return: Request payload stored in aiohttp MultipartWriter object instance
        """
        form_data = aiohttp.MultipartWriter("form-data")

        # Prepare file payload
        file_content, filename = await self._get_file_payload(file_content, filename, filepath)

        disposition = f'form-data; name="file"; filename="{filename}"'
        file_content.headers["Content-Disposition"] = disposition
        form_data.append_payload(file_content)

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

    async def _prepare_response(self, chunk: bytes, simplify: bool, task_uuid: str) -> dict:
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
                'seconds_remaining': status_data.get('task').get('remaining'),
                'info': f'For interactive analysis follow: https://app.any.run/tasks/{task_uuid}'
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

    @staticmethod
    async def _check_response_content_type(response: aiohttp.ClientResponse) -> None:
        """
        Checks if the response has a **stream-like** content-type

        :param response: API response
        :raises RunTimeException: If response has a different content-type
        """
        if not response.content_type.startswith(('text/event-stream', 'application/octet-stream')):
            if response.content_type.startswith('application/json'):
                raise RunTimeException((await response.json()).get('message'), response.status)
            raise RunTimeException('An unspecified error occurred while reading the stream', response.status)

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
    async def _get_file_payload(
            file_content: Optional[bytes] = None,
            filename: Optional[str] = None,
            filepath: Optional[str] = None,
    ) -> tuple[aiohttp.Payload, str]:
        """
        Generates file payload from received file content. Tries to open a file if given a file path

        :param file_content: File bytes to analyse.
        :param filename: Filename with file extension.
        :param filepath: Absolute path to file. If specified, automatically process file content and filename
        :return: Aiohttp Payload object instance
        :raises RunTimeException: If invalid filepath is received
        """
        if file_content and filename:
            return aiohttp.get_payload(file_content), filename
        elif filepath:
            if not os.path.isfile(filepath):
                raise RunTimeException(f'Received not valid filepath: {filepath}')

            async with aiofiles.open(filepath, mode='rb') as file:
                return aiohttp.get_payload(await file.read()), os.path.basename(filepath)
        else:
            raise RunTimeException(f'You must specify file_content with filename or filepath to start analysis')

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

    async def _download_sample(
            self,
            url: str,
            content_type: str,
            task_uuid: Union[UUID, str],
            filepath: Optional[str] = None
    ) -> Optional[bytes]:
        """
        Reads sample content from the stream

        :param url: Sample download url
        :param task_uuid: Task UUID
        :param filepath: Path to save the sample
        :return: Content bytes if **filepath** option is not specified
        """
        sample = b''
        response_data = await self._make_request_async('GET', url, parse_response=False)

        while True:
            # Read the next chunk from the event stream
            chunk = await response_data.content.readuntil(b'\n')
            # Skip the end of chunk and any meta information
            # https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events/Using_server-sent_events#fields
            if chunk == b'\n' or any(chunk.startswith(prefix) for prefix in [b"id", b"event", b"entry"]):
                continue
            if chunk == b'Not Found' or chunk == b'Content unavailable':
                raise RunTimeException('The requested file sample was not found', HTTPStatus.NOT_FOUND)

            # Stop interation if event stream is closed
            elif not chunk:
                break

            sample += chunk

        if filepath:
            await self._dump_response_content(sample, filepath, task_uuid, content_type)
            return

        return sample

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
        elif content_type == 'zip':
            await self._process_dump(f'{os.path.abspath(filepath)}/{task_uuid}_file_sample.zip', content, 'wb')
        elif content_type == 'pcap':
            await self._process_dump(f'{os.path.abspath(filepath)}/{task_uuid}_network_traffic_dump.zip', content, 'wb')
        else:
            await self._process_dump(
                f'{os.path.abspath(filepath)}/{task_uuid}_report_{content_type}.json', json.dumps(content), 'w'
            )

    @staticmethod
    async def _extract_sample_url(report: dict) -> str:
        """
        Returns file sample url

        :param report: Analysis summary
        :return: File sample download url
        :raises RunTimeException: If the file sample is private or analysis summary does not contain a file sample
        """
        if report.get('analysis').get('options').get('privateSample') == 'false':
            raise RunTimeException('The requested analysis contains private content')

        if report.get('analysis').get('content').get('mainObject').get('type') != 'file':
            raise RunTimeException('The requested analysis does not contain a file sample')

        return report.get('analysis').get('content').get('mainObject').get('permanentUrl')
