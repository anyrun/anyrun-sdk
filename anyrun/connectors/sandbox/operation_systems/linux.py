from uuid import UUID
from typing import Optional, Union

import aiohttp

from anyrun.connectors.sandbox.base_connector import BaseSandboxConnector
from anyrun.utils.config import Config
from anyrun.utils.utility_functions import execute_synchronously


class LinuxConnector(BaseSandboxConnector):
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
        :param enable_requests: Use requests.request to make api calls. May block the event loop
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

    def run_file_analysis(
            self,
            file_content: Optional[bytes] = None,
            filename: Optional[str] = None,
            filepath: Optional[str] = None,
            env_os: str = 'ubuntu',
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
            run_as_root: bool = False,
            obj_ext_extension: bool = True,
            user_tag: Optional[str] = None,
            task_rerun_uuid: Optional[str] = None
    ) -> Union[UUID, str]:
        """
        Initializes a new file analysis according to the specified parameters
        You can find extended documentation `here <https://any.run/api-documentation/#api-Analysis-PostAnalysis>`_
        Options: file_content and filename have higher priority then filepath option

        :param file_content: File bytes to analyse.
        :param filename: Filename with file extension.
        :param filepath: Absolute path to file. If specified, automatically process file content and filename
        :param env_os: Operation system. 
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
        :param run_as_root: Run file with superuser privileges
        :param obj_ext_extension: Change extension to valid
        :param user_tag: Append user tags to new analysis. Only characters a-z, A-Z, 0-9, hyphen (-), and comma (,)
            are allowed. Max tag length: 16 characters. Max unique tags per task: 8.
        :param task_rerun_uuid: Completed task identifier. Re-runs an existent task if uuid is specified. You can re-run
            task with new parameters
        :return: Task uuid
        """
        return execute_synchronously(
            self.run_file_analysis_async,
            file_content=file_content,
            filename=filename,
            filepath=filepath,
            env_os=env_os,
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
            run_as_root=run_as_root,
            obj_ext_extension=obj_ext_extension,
            task_rerun_uuid=task_rerun_uuid,
            user_tag=user_tag
        )

    async def run_file_analysis_async(
            self,
            file_content: Optional[bytes] = None,
            filename: Optional[str] = None,
            filepath: Optional[str] = None,
            env_os: str = 'ubuntu',
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
            run_as_root: bool = False,
            obj_ext_extension: bool = True,
            user_tag: Optional[str] = None,
            task_rerun_uuid: Optional[str] = None
    ) -> Union[UUID, str]:
        """
        Initializes a new file analysis according to the specified parameters
        You can find extended documentation `here <https://any.run/api-documentation/#api-Analysis-PostAnalysis>`_
        Options: file_content and filename have higher priority then filepath option

        :param file_content: File bytes to analyse.
        :param filename: Filename with file extension.
        :param filepath: Absolute path to file. If specified, automatically process file content and filename
        :param env_os: Operation system. 
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
        :param run_as_root: Run file with superuser privileges
        :param obj_ext_extension: Change extension to valid
        :param user_tag: Append user tags to new analysis. Only characters a-z, A-Z, 0-9, hyphen (-), and comma (,)
            are allowed. Max tag length: 16 characters. Max unique tags per task: 8.
        :param task_rerun_uuid: Completed task identifier. Re-runs an existent task if uuid is specified. You can re-run
            task with new parameters
        :return: Task uuid
        """
        url = f'{Config.ANY_RUN_API_URL}/analysis'

        body = await self._generate_multipart_request_body(
            file_content=file_content,
            filename=filename,
            filepath=filepath,
            env_os='linux',
            env_version='22.04.2',
            env_bitness='64',
            env_type='complete',
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
            obj_force_elevation=None,
            auto_confirm_uac=None,
            run_as_root=run_as_root,
            obj_ext_extension=obj_ext_extension,
            task_rerun_uuid=task_rerun_uuid,
            user_tag=user_tag
        )

        response_data = await self._make_request_async('POST', url, data=body)
        return response_data.get('data').get('taskid')

    def run_url_analysis(
            self,
            obj_url: str,
            env_os: str = 'ubuntu',
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
            obj_ext_browser: str = 'Google Chrome',
            obj_ext_extension: bool = True,
            user_tag: Optional[str] = None,
            task_rerun_uuid: Optional[str] = None
    ) -> Union[UUID, str]:
        """
        Initializes a new analysis according to the specified parameters
        You can find extended documentation `here <https://any.run/api-documentation/#api-Analysis-PostAnalysis>`_

        :param obj_url: Target URL. Size range 5-512. Example: (http/https)://(your-link)
        :param env_os: Operation system. 
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
        :param obj_ext_browser: Browser name. Supports: Google Chrome, Mozilla Firefox
        :param obj_ext_extension: Change extension to valid
        :param user_tag: Append user tags to new analysis. Only characters a-z, A-Z, 0-9, hyphen (-), and comma (,)
            are allowed. Max tag length: 16 characters. Max unique tags per task: 8.
        :param task_rerun_uuid: Completed task identifier. Re-runs an existent task if uuid is specified. You can re-run
            task with new parameters
        :return: Task uuid
        """
        return execute_synchronously(
            self.run_url_analysis_async,
            obj_url=obj_url,
            env_os=env_os,
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
            obj_ext_extension=obj_ext_extension,
            user_tag=user_tag
        )

    async def run_url_analysis_async(
            self,
            obj_url: str,
            env_os: str = 'ubuntu',
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
            obj_ext_browser: str = 'Google Chrome',
            obj_ext_extension: bool = True,
            user_tag: Optional[str] = None,
            task_rerun_uuid: Optional[str] = None,
    ) -> Union[UUID, str]:
        """
        Initializes a new analysis according to the specified parameters
        You can find extended documentation `here <https://any.run/api-documentation/#api-Analysis-PostAnalysis>`_

        :param obj_url: Target URL. Size range 5-512. Example: (http/https)://(your-link)
        :param env_os: Operation system. 
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
        :param obj_ext_browser: Browser name. Supports: Google Chrome, Mozilla Firefox
        :param obj_ext_extension: Change extension to valid
        :param user_tag: Append user tags to new analysis. Only characters a-z, A-Z, 0-9, hyphen (-), and comma (,)
            are allowed. Max tag length: 16 characters. Max unique tags per task: 8.
        :param task_rerun_uuid: Completed task identifier. Re-runs an existent task if uuid is specified. You can re-run
            task with new parameters
        :return: Task uuid
        """
        url = f'{Config.ANY_RUN_API_URL}/analysis'

        body = await self._generate_request_body(
            'url',
            obj_url=obj_url,
            env_os='linux',
            env_version='22.04.2',
            env_bitness='64',
            env_type='complete',
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
            obj_ext_extension=obj_ext_extension,
            user_tag=user_tag
        )
        response_data = await self._make_request_async('POST', url, json=body)
        return response_data.get('data').get('taskid')

    def run_download_analysis(
            self,
            obj_url: str,
            env_os: str = 'ubuntu',
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
            user_tag: Optional[str] = None,
            task_rerun_uuid: Optional[str] = None
    ) -> Union[UUID, str]:
        """
        Initializes a new analysis according to the specified parameters
        You can find extended documentation `here <https://any.run/api-documentation/#api-Analysis-PostAnalysis>`_

        :param obj_url: Target URL. Size range 5-512. Example: (http/https)://(your-link)
        :param env_os: Operation system. 
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
        :param obj_ext_useragent: User-Agent value.
        :param obj_ext_extension: Change extension to valid
        :param opt_privacy_hidesource: Option for hiding of source URL.
        :param user_tag: Append user tags to new analysis. Only characters a-z, A-Z, 0-9, hyphen (-), and comma (,)
            are allowed. Max tag length: 16 characters. Max unique tags per task: 8.
        :param task_rerun_uuid: Completed task identifier. Re-runs an existent task if uuid is specified. You can re-run
            task with new parameters
        :return: Task uuid
        """
        return execute_synchronously(
            self.run_download_analysis_async,
            obj_url=obj_url,
            env_os=env_os,
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
            opt_privacy_hidesource=opt_privacy_hidesource,
            user_tag=user_tag
        )

    async def run_download_analysis_async(
            self,
            obj_url: str,
            env_os: str = 'ubuntu',
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
            user_tag: Optional[str] = None,
            task_rerun_uuid: Optional[str] = None
    ) -> Union[UUID, str]:
        """
        Initializes a new analysis according to the specified parameters
        You can find extended documentation `here <https://any.run/api-documentation/#api-Analysis-PostAnalysis>`_

        :param obj_url: Target URL. Size range 5-512. Example: (http/https)://(your-link)
        :param env_os: Operation system. 
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
        :param obj_ext_useragent: User-Agent value.
        :param obj_ext_extension: Change extension to valid
        :param opt_privacy_hidesource: Option for hiding of source URL.
        :param user_tag: Append user tags to new analysis. Only characters a-z, A-Z, 0-9, hyphen (-), and comma (,)
            are allowed. Max tag length: 16 characters. Max unique tags per task: 8.
        :param task_rerun_uuid: Completed task identifier. Re-runs an existent task if uuid is specified. You can re-run
            task with new parameters
        :return: Task uuid
        """
        url = f'{Config.ANY_RUN_API_URL}/analysis'

        body = await self._generate_request_body(
            'download',
            obj_url=obj_url,
            env_os='linux',
            env_version='22.04.2',
            env_bitness='64',
            env_type='complete',
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
            opt_privacy_hidesource=opt_privacy_hidesource,
            user_tag=user_tag
        )

        response_data = await self._make_request_async('POST', url, json=body)
        return response_data.get('data').get('taskid')
