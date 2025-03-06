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


class SandBoxConnector(AnyRunConnector):
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
            task_uuid: UUID,
            simplify: bool = False
    ) -> Optional[dict]:
        """
        Returns a submission analysis report by task ID

        :param task_uuid: Task uuid
        :param simplify: Return None if no threats found during analysis
        :return: Complete report in **json** format
        """
        return execute_synchronously(self.get_analysis_report_async, task_uuid, simplify)

    async def get_analysis_report_async(
            self,
            task_uuid: UUID,
            simplify: bool = False
    ) -> Optional[dict]:
        """
        Returns a submission analysis report by task ID

        :param task_uuid: Task uuid
        :param simplify: Return None if no threats has been detected
        :return: Complete report in **json** format
        """
        url = f'{Config.ANY_RUN_API_URL}/analysis/{task_uuid}'

        response_data = await self._make_request_async('GET', url)

        if simplify and not await self._find_threats(response_data):
            return
        return response_data.get('data')

    def add_time_to_task(self, task_uuid: UUID) -> dict:
        """
        Adds 60 seconds of execution time to an active task. The task must belong to the current user

        :param task_uuid: Task uuid
        :return: API response json
        """
        return execute_synchronously(self.add_time_to_task_async, task_uuid)

    async def add_time_to_task_async(self, task_uuid: UUID) -> dict:
        """
        Adds 60 seconds of execution time to an active task. The task must belong to the current user

        :param task_uuid: Task uuid
        :return: API response json
        """
        url = f'{Config.ANY_RUN_API_URL}/analysis/addtime/{task_uuid}'
        return await self._make_request_async('PATCH', url)

    def stop_task(self, task_uuid: UUID) -> dict:
        """
        Stops running task. The task must belong to the current user

        :param task_uuid: Task uuid
        :return: API response json
        """
        return execute_synchronously(self.stop_task_async, task_uuid)

    async def stop_task_async(self, task_uuid: UUID) -> dict:
        """
        Stops running task. The task must belong to the current user

        :param task_uuid: Task uuid
        :return: API response json
        """
        url = f'{Config.ANY_RUN_API_URL}/analysis/stop/{task_uuid}'
        return await self._make_request_async('PATCH', url)

    def delete_task(self, task_uuid: UUID) -> dict:
        """
        Deletes running task. The task must belong to the current user

        :param task_uuid: Task uuid
        :return: API response json
        """
        return execute_synchronously(self.delete_task_async, task_uuid)

    async def delete_task_async(self, task_uuid: UUID) -> dict:
        """
        Deletes running task. The task must belong to the current user

        :param task_uuid: Task uuid
        :return: API response json
        """
        url = f'{Config.ANY_RUN_API_URL}/analysis/delete/{task_uuid}'
        return await self._make_request_async('DELETE', url)

    def get_task_status(self, task_uuid: UUID, simplify: bool = True) -> Iterator[dict]:
        """
        Information about the task status is sent to the event stream.
        Returns a synchronous iterator to process the actual status until the task is completed.

        :param task_uuid: Task uuid
        :param simplify: If enabled, returns a simplified dict with the remaining scan time and the current task status
            else returns the entire response
        """
        return execute_async_iterator(self.get_task_status_async(task_uuid, simplify))

    async def get_task_status_async(self, task_uuid: UUID, simplify: bool = True) -> AsyncIterator[dict]:
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

    def get_user_presets(self) -> dict:
        """
        Request user's presets

        :return: API response json
        """
        return execute_synchronously(self.get_user_presets_async)

    async def get_user_presets_async(self) -> dict:
        """
        Request user's presets

        :return: API response json
        """
        url = f'{Config.ANY_RUN_API_URL}/user/presets'
        return await self._make_request_async('GET', url)

    def run_file_analysis(
            self,
            file: Union[str, bytes],
            env_os: str = 'windows',
            env_version: str = '10',
            env_bitness: int = 64,
            env_type: str = 'complete',
            env_locale: str = 'en-US',
            opt_network_connect: bool = True,
            opt_network_fakenet: bool = False,
            opt_network_tor: bool = False,
            opt_network_geo: str = 'fastest',
            opt_network_mitm: bool = False,
            opt_network_residential_proxy: bool = False,
            opt_network_residential_proxy_geo: str = 'fastest',
            opt_kernel_heavyevasion: bool = False,
            opt_privacy_type: str = 'bylink',
            opt_timeout: int = 60,
            opt_automated_interactivity: bool = True,
            obj_ext_startfolder: str = 'temp',
            obj_ext_cmd: Optional[str] = None,
            obj_force_elevation: bool = False,
            auto_confirm_uac: bool = True,
            run_as_root: bool = False,
            obj_ext_extension: bool = True,
            task_rerun_uuid: Optional[str] = None
    ) -> str:
        """
        Initializes a new file analysis according to the specified parameters
        You can find extended documentation `here <https://any.run/api-documentation/#api-Analysis-PostAnalysis>`_

        :param file: File to analyse. Path to file, or bytes object
        :param env_os: Operation System. Supports: **windows, linux**
        :param env_version: Version of OS. Supports: 7, 10, 11 for **windows** and 22.04.2 for **linux**
        :param env_bitness: Bitness of Operation System. Supports 32, 64 for **windows** and 32 for **linux**
        :param env_type: Environment preset type. Supports clean, office, complete for **windows** and
            office for **linux**
        :param env_locale: Operation system's language. Use locale identifier or country name (Ex: "en-US" or "Brazil").
            Case insensitive.
        :param opt_network_connect: Network connection state
        :param opt_network_fakenet: FakeNet feature status
        :param opt_network_tor: TOR using
        :param opt_network_geo: Tor geo location option. Example: US, AU
        :param opt_network_mitm: HTTPS MITM proxy option.
        :param opt_network_residential_proxy: Residential proxy using
        :param opt_network_residential_proxy_geo: Residential proxy geo location option. Example: US, AU
        :param opt_kernel_heavyevasion: Heavy evasion option
        :param opt_privacy_type: Privacy settings. Supports: public, bylink, owner, byteam
        :param opt_timeout: Timeout option. Size range: 10-660
        :param opt_automated_interactivity: Automated Interactivity (ML) option
        :param obj_ext_startfolder: Start object from. Supports: desktop, home, downloads, appdata, temp, windows,
            root
        :param obj_ext_cmd: Optional command line.
        :param obj_force_elevation: Forces the file to execute with elevated privileges and an elevated token
            (for PE32, PE32+, PE64 files only). Use with the parameter env_os: **windows**
        :param auto_confirm_uac: Auto confirm Windows UAC requests. Use with the parameter env_os: **windows**
        :param run_as_root: Run file with superuser privileges. Use with the parameter env_os: **linux**
        :param obj_ext_extension: Change extension to valid
        :param task_rerun_uuid: Completed task identifier. Re-runs an existent task if uuid is specified. You can re-run
            task with new parameters
        :return: Task uuid
        """
        return execute_synchronously(
            self.run_file_analysis_async,
            file=file,
            env_os=env_os,
            env_version=env_version,
            env_bitness=env_bitness,
            env_type=env_type,
            env_locale=env_locale,
            opt_network_connect=opt_network_connect,
            opt_network_fakenet=opt_network_fakenet,
            opt_network_tor=opt_network_tor,
            opt_network_geo=opt_network_geo,
            opt_network_mitm=opt_network_mitm,
            opt_network_residential_proxy=opt_network_residential_proxy,
            opt_network_residential_proxy_geo=opt_network_residential_proxy_geo,
            opt_kernel_heavyevasion=opt_kernel_heavyevasion,
            opt_privacy_type=opt_privacy_type,
            opt_timeout=opt_timeout,
            opt_automated_interactivity=opt_automated_interactivity,
            obj_ext_startfolder=obj_ext_startfolder,
            obj_ext_cmd=obj_ext_cmd,
            obj_force_elevation=obj_force_elevation,
            auto_confirm_uac=auto_confirm_uac,
            run_as_root=run_as_root,
            obj_ext_extension=obj_ext_extension,
            task_rerun_uuid=task_rerun_uuid
        )

    async def run_file_analysis_async(
            self,
            file: Union[str, bytes],
            env_os: str = 'windows',
            env_version: str = '10',
            env_bitness: int = 64,
            env_type: str = 'complete',
            env_locale: str = 'en-US',
            opt_network_connect: bool = True,
            opt_network_fakenet: bool = False,
            opt_network_tor: bool = False,
            opt_network_geo: str = 'fastest',
            opt_network_mitm: bool = False,
            opt_network_residential_proxy: bool = False,
            opt_network_residential_proxy_geo: str = 'fastest',
            opt_kernel_heavyevasion: bool = False,
            opt_privacy_type: str = 'bylink',
            opt_timeout: int = 60,
            opt_automated_interactivity: bool = True,
            obj_ext_startfolder: str = 'temp',
            obj_ext_cmd: Optional[str] = None,
            obj_force_elevation: bool = False,
            auto_confirm_uac: bool = True,
            run_as_root: bool = False,
            obj_ext_extension: bool = True,
            task_rerun_uuid: Optional[str] = None
    ) -> str:
        """
        Initializes a new file analysis according to the specified parameters
        You can find extended documentation `here <https://any.run/api-documentation/#api-Analysis-PostAnalysis>`_

        :param file: File to analyse. Path to file, or bytes object
        :param env_os: Operation System. Supports: **windows, linux**
        :param env_version: Version of OS. Supports: 7, 10, 11 for **windows** and 22.04.2 for **linux**
        :param env_bitness: Bitness of Operation System. Supports 32, 64 for **windows** and 32 for **linux**
        :param env_type: Environment preset type. Supports clean, office, complete for **windows** and
            office for **linux**
        :param env_locale: Operation system's language. Use locale identifier or country name (Ex: "en-US" or "Brazil").
            Case insensitive.
        :param opt_network_connect: Network connection state
        :param opt_network_fakenet: FakeNet feature status
        :param opt_network_tor: TOR using
        :param opt_network_geo: Tor geo location option. Example: US, AU
        :param opt_network_mitm: HTTPS MITM proxy option.
        :param opt_network_residential_proxy: Residential proxy using
        :param opt_network_residential_proxy_geo: Residential proxy geo location option. Example: US, AU
        :param opt_kernel_heavyevasion: Heavy evasion option
        :param opt_privacy_type: Privacy settings. Supports: public, bylink, owner, byteam
        :param opt_timeout: Timeout option. Size range: 10-660
        :param opt_automated_interactivity: Automated Interactivity (ML) option
        :param obj_ext_startfolder: Start object from. Supports: desktop, home, downloads, appdata, temp, windows,
            root
        :param obj_ext_cmd: Optional command line.
        :param obj_force_elevation: Forces the file to execute with elevated privileges and an elevated token
            (for PE32, PE32+, PE64 files only). Use with the parameter env_os: **windows**
        :param auto_confirm_uac: Auto confirm Windows UAC requests. Use with the parameter env_os: **windows**
        :param run_as_root: Run file with superuser privileges. Use with the parameter env_os: **linux**
        :param obj_ext_extension: Change extension to valid
        :param task_rerun_uuid: Completed task identifier. Re-runs an existent task if uuid is specified. You can re-run
            task with new parameters
        :return: Task uuid
        """
        url = f'{Config.ANY_RUN_API_URL}/analysis'

        body = await self._generate_multipart_request_body(
            file,
            env_os=env_os,
            env_version=env_version,
            env_bitness=env_bitness,
            env_type=env_type,
            env_locale=env_locale,
            opt_network_connect=opt_network_connect,
            opt_network_fakenet=opt_network_fakenet,
            opt_network_tor=opt_network_tor,
            opt_network_geo=opt_network_geo,
            opt_network_mitm=opt_network_mitm,
            opt_network_residential_proxy=opt_network_residential_proxy,
            opt_network_residential_proxy_geo=opt_network_residential_proxy_geo,
            opt_kernel_heavyevasion=opt_kernel_heavyevasion,
            opt_privacy_type=opt_privacy_type,
            opt_timeout=opt_timeout,
            opt_automated_interactivity=opt_automated_interactivity,
            obj_ext_startfolder=obj_ext_startfolder,
            obj_ext_cmd=obj_ext_cmd,
            obj_force_elevation=obj_force_elevation,
            auto_confirm_uac=auto_confirm_uac,
            run_as_root=run_as_root,
            obj_ext_extension=obj_ext_extension,
            task_rerun_uuid=task_rerun_uuid,
        )

        response_data = await self._make_request_async('POST', url, data=body)
        return response_data.get('data').get('taskid')

    def run_url_analysis(
            self,
            obj_url: str,
            env_os: str = 'windows',
            env_version: str = '10',
            env_bitness: int = 64,
            env_type: str = 'complete',
            env_locale: str = 'en-US',
            opt_network_connect: bool = True,
            opt_network_fakenet: bool = False,
            opt_network_tor: bool = False,
            opt_network_geo: str = 'fastest',
            opt_network_mitm: bool = False,
            opt_network_residential_proxy: bool = False,
            opt_network_residential_proxy_geo: str = 'fastest',
            opt_kernel_heavyevasion: bool = False,
            opt_privacy_type: str = 'bylink',
            opt_timeout: int = 60,
            opt_automated_interactivity: bool = True,
            obj_ext_browser: str = 'Microsoft Edge',
            obj_ext_extension: bool = True,
            task_rerun_uuid: Optional[str] = None
    ) -> str:
        """
        Initializes a new analysis according to the specified parameters
        You can find extended documentation `here <https://any.run/api-documentation/#api-Analysis-PostAnalysis>`_
        
        :param obj_url: Target URL. Size range 5-512. Example: (http/https)://(your-link)
        :param env_os: Operation System. Supports: **windows, linux**
        :param env_version: Version of OS. Supports: 7, 10, 11 for **windows** and 22.04.2 for **linux**
        :param env_bitness: Bitness of Operation System. Supports 32, 64 for **windows** and 32 for **linux**
        :param env_type: Environment preset type. Supports clean, office, complete for **windows** and
            office for **linux**
        :param env_locale: Operation system's language. Use locale identifier or country name (Ex: "en-US" or "Brazil").
            Case insensitive.
        :param opt_network_connect: Network connection state
        :param opt_network_fakenet: FakeNet feature status
        :param opt_network_tor: TOR using
        :param opt_network_geo: Tor geo location option. Example: US, AU
        :param opt_network_mitm: HTTPS MITM proxy option.
        :param opt_network_residential_proxy: Residential proxy using
        :param opt_network_residential_proxy_geo: Residential proxy geo location option. Example: US, AU
        :param opt_kernel_heavyevasion: Heavy evasion option
        :param opt_privacy_type: Privacy settings. Supports: public, bylink, owner, byteam
        :param opt_timeout: Timeout option. Size range: 10-660
        :param opt_automated_interactivity: Automated Interactivity (ML) option
        :param task_rerun_uuid: UUID of the task to be restarted.
        :param obj_ext_browser: Browser name. Supports: Google Chrome
            Mozilla Firefox, Internet Explorer, Microsoft Edge for **windows** and Google Chrome, Mozilla Firefox
            for **linux**
        :param obj_ext_extension: Change extension to valid
        :param task_rerun_uuid: Completed task identifier. Re-runs an existent task if uuid is specified. You can re-run
            task with new parameters
        :return: Task uuid
        """
        return execute_synchronously(
            self.run_url_analysis_async,
            obj_url=obj_url,
            env_os=env_os,
            env_version=env_version,
            env_bitness=env_bitness,
            env_type=env_type,
            env_locale=env_locale,
            opt_network_connect=opt_network_connect,
            opt_network_fakenet=opt_network_fakenet,
            opt_network_tor=opt_network_tor,
            opt_network_geo=opt_network_geo,
            opt_network_mitm=opt_network_mitm,
            opt_network_residential_proxy=opt_network_residential_proxy,
            opt_network_residential_proxy_geo=opt_network_residential_proxy_geo,
            opt_kernel_heavyevasion=opt_kernel_heavyevasion,
            opt_privacy_type=opt_privacy_type,
            opt_timeout=opt_timeout,
            opt_automated_interactivity=opt_automated_interactivity,
            task_rerun_uuid=task_rerun_uuid,
            obj_ext_browser=obj_ext_browser,
            obj_ext_extension=obj_ext_extension
        )

    async def run_url_analysis_async(
            self,
            obj_url: str,
            env_os: str = 'windows',
            env_version: str = '10',
            env_bitness: int = 64,
            env_type: str = 'complete',
            env_locale: str = 'en-US',
            opt_network_connect: bool = True,
            opt_network_fakenet: bool = False,
            opt_network_tor: bool = False,
            opt_network_geo: str = 'fastest',
            opt_network_mitm: bool = False,
            opt_network_residential_proxy: bool = False,
            opt_network_residential_proxy_geo: str = 'fastest',
            opt_kernel_heavyevasion: bool = False,
            opt_privacy_type: str = 'bylink',
            opt_timeout: int = 60,
            opt_automated_interactivity: bool = True,
            obj_ext_browser: str = 'Microsoft Edge',
            obj_ext_extension: bool = True,
            task_rerun_uuid: Optional[str] = None
    ) -> str:
        """
        Initializes a new analysis according to the specified parameters
        You can find extended documentation `here <https://any.run/api-documentation/#api-Analysis-PostAnalysis>`_
        
        :param obj_url: Target URL. Size range 5-512. Example: (http/https)://(your-link)
        :param env_os: Operation System. Supports: **windows, linux**
        :param env_version: Version of OS. Supports: 7, 10, 11 for **windows** and 22.04.2 for **linux**
        :param env_bitness: Bitness of Operation System. Supports 32, 64 for **windows** and 32 for **linux**
        :param env_type: Environment preset type. Supports clean, office, complete for **windows** and
            office for **linux**
        :param env_locale: Operation system's language. Use locale identifier or country name (Ex: "en-US" or "Brazil").
            Case insensitive.
        :param opt_network_connect: Network connection state
        :param opt_network_fakenet: FakeNet feature status
        :param opt_network_tor: TOR using
        :param opt_network_geo: Tor geo location option. Example: US, AU
        :param opt_network_mitm: HTTPS MITM proxy option.
        :param opt_network_residential_proxy: Residential proxy using
        :param opt_network_residential_proxy_geo: Residential proxy geo location option. Example: US, AU
        :param opt_kernel_heavyevasion: Heavy evasion option
        :param opt_privacy_type: Privacy settings. Supports: public, bylink, owner, byteam
        :param opt_timeout: Timeout option. Size range: 10-660
        :param opt_automated_interactivity: Automated Interactivity (ML) option
        :param task_rerun_uuid: UUID of the task to be restarted.
        :param obj_ext_browser: Browser name. Supports: Google Chrome
            Mozilla Firefox, Internet Explorer, Microsoft Edge for **windows** and Google Chrome, Mozilla Firefox
            for **linux**
        :param obj_ext_extension: Change extension to valid
        :param task_rerun_uuid: Completed task identifier. Re-runs an existent task if uuid is specified. You can re-run
            task with new parameters
        :return: Task uuid
        """
        url = f'{Config.ANY_RUN_API_URL}/analysis'

        body = await self._generate_request_body(
            'url',
            obj_url=obj_url,
            env_os=env_os,
            env_version=env_version,
            env_bitness=env_bitness,
            env_type=env_type,
            env_locale=env_locale,
            opt_network_connect=opt_network_connect,
            opt_network_fakenet=opt_network_fakenet,
            opt_network_tor=opt_network_tor,
            opt_network_geo=opt_network_geo,
            opt_network_mitm=opt_network_mitm,
            opt_network_residential_proxy=opt_network_residential_proxy,
            opt_network_residential_proxy_geo=opt_network_residential_proxy_geo,
            opt_kernel_heavyevasion=opt_kernel_heavyevasion,
            opt_privacy_type=opt_privacy_type,
            opt_timeout=opt_timeout,
            opt_automated_interactivity=opt_automated_interactivity,
            task_rerun_uuid=task_rerun_uuid,
            obj_ext_browser=obj_ext_browser,
            obj_ext_extension=obj_ext_extension
        )
        response_data = await self._make_request_async('POST', url, json=body)
        return response_data.get('data').get('taskid')

    def run_download_analysis(
            self,
            obj_url: str,
            env_os: str = 'windows',
            env_version: str = '10',
            env_bitness: int = 64,
            env_type: str = 'complete',
            env_locale: str = 'en-US',
            opt_network_connect: bool = True,
            opt_network_fakenet: bool = False,
            opt_network_tor: bool = False,
            opt_network_geo: str = 'fastest',
            opt_network_mitm: bool = False,
            opt_network_residential_proxy: bool = False,
            opt_network_residential_proxy_geo: str = 'fastest',
            opt_kernel_heavyevasion: bool = False,
            opt_privacy_type: str = 'bylink',
            opt_timeout: int = 60,
            opt_automated_interactivity: bool = True,
            obj_ext_startfolder: str = 'temp',
            obj_ext_cmd: Optional[str] = None,
            obj_ext_useragent: Optional[str] = None,
            obj_ext_extension: bool = True,
            opt_privacy_hidesource: bool = False,
            task_rerun_uuid: Optional[str] = None
    ) -> str:
        """
        Initializes a new analysis according to the specified parameters
        You can find extended documentation `here <https://any.run/api-documentation/#api-Analysis-PostAnalysis>`_
        
        :param obj_url: Target URL. Size range 5-512. Example: (http/https)://(your-link)
        :param env_os: Operation System. Supports: **windows, linux**
        :param env_version: Version of OS. Supports: 7, 10, 11 for **windows** and 22.04.2 for **linux**
        :param env_bitness: Bitness of Operation System. Supports 32, 64 for **windows** and 32 for **linux**
        :param env_type: Environment preset type. Supports clean, office, complete for **windows** and
            office for **linux**
        :param env_locale: Operation system's language. Use locale identifier or country name (Ex: "en-US" or "Brazil").
            Case insensitive.
        :param opt_network_connect: Network connection state
        :param opt_network_fakenet: FakeNet feature status
        :param opt_network_tor: TOR using
        :param opt_network_geo: Tor geo location option. Example: US, AU
        :param opt_network_mitm: HTTPS MITM proxy option.
        :param opt_network_residential_proxy: Residential proxy using
        :param opt_network_residential_proxy_geo: Residential proxy geo location option. Example: US, AU
        :param opt_kernel_heavyevasion: Heavy evasion option
        :param opt_privacy_type: Privacy settings. Supports: public, bylink, owner, byteam
        :param opt_timeout: Timeout option. Size range: 10-660
        :param opt_automated_interactivity: Automated Interactivity (ML) option
        :param obj_ext_startfolder: Start object from. Supports: desktop, home, downloads, appdata, temp, windows,
            root
        :param task_rerun_uuid: UUID of the task to be restarted.
        :param obj_ext_cmd: Optional command line.
        :param obj_ext_useragent: User-Agent value.
        :param obj_ext_extension: Change extension to valid
        :param opt_privacy_hidesource: Option for hiding of source URL.
        :param task_rerun_uuid: Completed task identifier. Re-runs an existent task if uuid is specified. You can re-run
            task with new parameters
        :return: Task uuid
        """
        return execute_synchronously(
            self.run_download_analysis_async,
            obj_url=obj_url,
            env_os=env_os,
            env_version=env_version,
            env_bitness=env_bitness,
            env_type=env_type,
            env_locale=env_locale,
            opt_network_connect=opt_network_connect,
            opt_network_fakenet=opt_network_fakenet,
            opt_network_tor=opt_network_tor,
            opt_network_geo=opt_network_geo,
            opt_network_mitm=opt_network_mitm,
            opt_network_residential_proxy=opt_network_residential_proxy,
            opt_network_residential_proxy_geo=opt_network_residential_proxy_geo,
            opt_kernel_heavyevasion=opt_kernel_heavyevasion,
            opt_privacy_type=opt_privacy_type,
            opt_timeout=opt_timeout,
            opt_automated_interactivity=opt_automated_interactivity,
            obj_ext_startfolder=obj_ext_startfolder,
            task_rerun_uuid=task_rerun_uuid,
            obj_ext_cmd=obj_ext_cmd,
            obj_ext_useragent=obj_ext_useragent,
            obj_ext_extension=obj_ext_extension,
            opt_privacy_hidesource=opt_privacy_hidesource
        )

    async def run_download_analysis_async(
            self,
            obj_url: str,
            env_os: str = 'windows',
            env_version: str = '10',
            env_bitness: int = 64,
            env_type: str = 'complete',
            env_locale: str = 'en-US',
            opt_network_connect: bool = True,
            opt_network_fakenet: bool = False,
            opt_network_tor: bool = False,
            opt_network_geo: str = 'fastest',
            opt_network_mitm: bool = False,
            opt_network_residential_proxy: bool = False,
            opt_network_residential_proxy_geo: str = 'fastest',
            opt_kernel_heavyevasion: bool = False,
            opt_privacy_type: str = 'bylink',
            opt_timeout: int = 60,
            opt_automated_interactivity: bool = True,
            obj_ext_startfolder: str = 'temp',
            obj_ext_cmd: Optional[str] = None,
            obj_ext_useragent: Optional[str] = None,
            obj_ext_extension: bool = True,
            opt_privacy_hidesource: bool = False,
            task_rerun_uuid: Optional[str] = None
    ) -> str:
        """
        Initializes a new analysis according to the specified parameters
        You can find extended documentation `here <https://any.run/api-documentation/#api-Analysis-PostAnalysis>`_
        
        :param obj_url: Target URL. Size range 5-512. Example: (http/https)://(your-link)
        :param env_os: Operation System. Supports: **windows, linux**
        :param env_version: Version of OS. Supports: 7, 10, 11 for **windows** and 22.04.2 for **linux**
        :param env_bitness: Bitness of Operation System. Supports 32, 64 for **windows** and 32 for **linux**
        :param env_type: Environment preset type. Supports clean, office, complete for **windows** and
            office for **linux**
        :param env_locale: Operation system's language. Use locale identifier or country name (Ex: "en-US" or "Brazil").
            Case insensitive.
        :param opt_network_connect: Network connection state
        :param opt_network_fakenet: FakeNet feature status
        :param opt_network_tor: TOR using
        :param opt_network_geo: Tor geo location option. Example: US, AU
        :param opt_network_mitm: HTTPS MITM proxy option.
        :param opt_network_residential_proxy: Residential proxy using
        :param opt_network_residential_proxy_geo: Residential proxy geo location option. Example: US, AU
        :param opt_kernel_heavyevasion: Heavy evasion option
        :param opt_privacy_type: Privacy settings. Supports: public, bylink, owner, byteam
        :param opt_timeout: Timeout option. Size range: 10-660
        :param opt_automated_interactivity: Automated Interactivity (ML) option
        :param obj_ext_startfolder: Start object from. Supports: desktop, home, downloads, appdata, temp, windows,
            root
        :param task_rerun_uuid: UUID of the task to be restarted.
        :param obj_ext_cmd: Optional command line.
        :param obj_ext_useragent: User-Agent value.
        :param obj_ext_extension: Change extension to valid
        :param opt_privacy_hidesource: Option for hiding of source URL.
        :param task_rerun_uuid: Completed task identifier. Re-runs an existent task if uuid is specified. You can re-run
            task with new parameters
        :return: Task uuid
        """
        url = f'{Config.ANY_RUN_API_URL}/analysis'

        body = await self._generate_request_body(
            'download',
            obj_url=obj_url,
            env_os=env_os,
            env_version=env_version,
            env_bitness=env_bitness,
            env_type=env_type,
            env_locale=env_locale,
            opt_network_connect=opt_network_connect,
            opt_network_fakenet=opt_network_fakenet,
            opt_network_tor=opt_network_tor,
            opt_network_geo=opt_network_geo,
            opt_network_mitm=opt_network_mitm,
            opt_network_residential_proxy=opt_network_residential_proxy,
            opt_network_residential_proxy_geo=opt_network_residential_proxy_geo,
            opt_kernel_heavyevasion=opt_kernel_heavyevasion,
            opt_privacy_type=opt_privacy_type,
            opt_timeout=opt_timeout,
            opt_automated_interactivity=opt_automated_interactivity,
            obj_ext_startfolder=obj_ext_startfolder,
            task_rerun_uuid=task_rerun_uuid,
            obj_ext_cmd=obj_ext_cmd,
            obj_ext_useragent=obj_ext_useragent,
            obj_ext_extension=obj_ext_extension,
            opt_privacy_hidesource=opt_privacy_hidesource
        )

        response_data = await self._make_request_async('POST', url, json=body)
        return response_data.get('data').get('taskid')

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
            if value is not None:
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
        request_body = {param: value for param, value in params.items() if value is not None}
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

    @staticmethod
    async def _find_threats(response_data: dict) -> Optional[bool]:
        """
        Checks whether threats are detected during analysis

        :param response_data: Report in **json** format
        :return: **True** if threats were detected else **None**
        """
        if (
            response_data.get('data')
            .get('analysis')
            .get('scores')
            .get('verdict')
            .get('threatLevelText') != 'No threats detected'
           ):
            return True

    @staticmethod
    async def _check_response_content_type(response: aiohttp.ClientResponse) -> None:
        """
        Checks if the response has **text/event-stream** content-type

        :param response: API response
        :raises RunTimeException: If response has a different content-type
        """
        if not response.content_type.startswith('text/event-stream'):
            raise RunTimeException(
                {
                    'status': 'error',
                    'code': response.status,
                    'description': (await response.json()).get('message')
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
