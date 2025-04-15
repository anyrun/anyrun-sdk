from uuid import UUID
from typing import Optional, Union

import aiohttp

from anyrun.connectors.sandbox.base_connector import BaseSandboxConnector
from anyrun.utils.config import Config
from anyrun.utils.utility_functions import execute_synchronously


class WindowsConnector(BaseSandboxConnector):
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

    def run_file_analysis(
            self,
            file: Union[str, bytes],
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
            obj_ext_extension: bool = True,
            task_rerun_uuid: Optional[str] = None
    ) -> Union[UUID, str]:
        """
        Initializes a new file analysis according to the specified parameters
        You can find extended documentation `here <https://any.run/api-documentation/#api-Analysis-PostAnalysis>`_

        :param file: File to analyse. Path to file, or bytes object
        :param env_version: Version of OS. Supports: 7, 10, 11
        :param env_bitness: Bitness of Operation System. Supports 32, 64
        :param env_type: Environment preset type. Supports clean, office, complete
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
            (for PE32, PE32+, PE64 files only)
        :param auto_confirm_uac: Auto confirm Windows UAC requests.
        :param obj_ext_extension: Change extension to valid
        :param task_rerun_uuid: Completed task identifier. Re-runs an existent task if uuid is specified. You can re-run
            task with new parameters
        :return: Task uuid
        """
        return execute_synchronously(
            self.run_file_analysis_async,
            file=file,
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
            obj_ext_extension=obj_ext_extension,
            task_rerun_uuid=task_rerun_uuid
        )

    async def run_file_analysis_async(
            self,
            file: Union[str, bytes],
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
            obj_ext_extension: bool = True,
            task_rerun_uuid: Optional[str] = None
    ) -> Union[UUID, str]:
        """
        Initializes a new file analysis according to the specified parameters
        You can find extended documentation `here <https://any.run/api-documentation/#api-Analysis-PostAnalysis>`_

        :param file: File to analyse. Path to file, or bytes object
        :param env_version: Version of OS. Supports: 7, 10, 11
        :param env_bitness: Bitness of Operation System. Supports 32, 64
        :param env_type: Environment preset type. Supports clean, office, complete
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
            (for PE32, PE32+, PE64 files only)
        :param auto_confirm_uac: Auto confirm Windows UAC requests.
        :param obj_ext_extension: Change extension to valid
        :param task_rerun_uuid: Completed task identifier. Re-runs an existent task if uuid is specified. You can re-run
            task with new parameters
        :return: Task uuid
        """
        url = f'{Config.ANY_RUN_API_URL}/analysis'

        body = await self._generate_multipart_request_body(
            file,
            env_os='windows',
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
            obj_ext_extension=obj_ext_extension,
            task_rerun_uuid=task_rerun_uuid,
        )

        response_data = await self._make_request_async('POST', url, data=body)
        return response_data.get('data').get('taskid')

    def run_url_analysis(
            self,
            obj_url: str,
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
    ) -> Union[UUID, str]:
        """
        Initializes a new analysis according to the specified parameters
        You can find extended documentation `here <https://any.run/api-documentation/#api-Analysis-PostAnalysis>`_
        
        :param obj_url: Target URL. Size range 5-512. Example: (http/https)://(your-link)
        :param env_version: Version of OS. Supports: 7, 10, 11
        :param env_bitness: Bitness of Operation System. Supports 32, 64
        :param env_type: Environment preset type. Supports clean, office, complete
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
        :param obj_ext_browser: Browser name. Supports: Google Chrome Mozilla Firefox, Internet Explorer, Microsoft Edge
        :param obj_ext_extension: Change extension to valid
        :param task_rerun_uuid: Completed task identifier. Re-runs an existent task if uuid is specified. You can re-run
            task with new parameters
        :return: Task uuid
        """
        return execute_synchronously(
            self.run_url_analysis_async,
            obj_url=obj_url,
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
    ) -> Union[UUID, str]:
        """
        Initializes a new analysis according to the specified parameters
        You can find extended documentation `here <https://any.run/api-documentation/#api-Analysis-PostAnalysis>`_

        :param obj_url: Target URL. Size range 5-512. Example: (http/https)://(your-link)
        :param env_version: Version of OS. Supports: 7, 10, 11
        :param env_bitness: Bitness of Operation System. Supports 32, 64
        :param env_type: Environment preset type. Supports clean, office, complete
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
        :param obj_ext_browser: Browser name. Supports: Google Chrome Mozilla Firefox, Internet Explorer, Microsoft Edge
        :param obj_ext_extension: Change extension to valid
        :param task_rerun_uuid: Completed task identifier. Re-runs an existent task if uuid is specified. You can re-run
            task with new parameters
        :return: Task uuid
        """
        url = f'{Config.ANY_RUN_API_URL}/analysis'

        body = await self._generate_request_body(
            'url',
            obj_url=obj_url,
            env_os='windows',
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
    ) -> Union[UUID, str]:
        """
        Initializes a new analysis according to the specified parameters
        You can find extended documentation `here <https://any.run/api-documentation/#api-Analysis-PostAnalysis>`_
        
        :param obj_url: Target URL. Size range 5-512. Example: (http/https)://(your-link)
        :param env_version: Version of OS. Supports: 7, 10, 11
        :param env_bitness: Bitness of Operation System. Supports 32, 64
        :param env_type: Environment preset type. Supports clean, office, complete
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
        :param task_rerun_uuid: Completed task identifier. Re-runs an existent task if uuid is specified. You can re-run
            task with new parameters
        :return: Task uuid
        """
        return execute_synchronously(
            self.run_download_analysis_async,
            obj_url=obj_url,
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
    ) -> Union[UUID, str]:
        """
        Initializes a new analysis according to the specified parameters
        You can find extended documentation `here <https://any.run/api-documentation/#api-Analysis-PostAnalysis>`_

        :param obj_url: Target URL. Size range 5-512. Example: (http/https)://(your-link)
        :param env_version: Version of OS. Supports: 7, 10, 11
        :param env_bitness: Bitness of Operation System. Supports 32, 64
        :param env_type: Environment preset type. Supports clean, office, complete
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
        :param task_rerun_uuid: Completed task identifier. Re-runs an existent task if uuid is specified. You can re-run
            task with new parameters
        :return: Task uuid
        """
        url = f'{Config.ANY_RUN_API_URL}/analysis'

        body = await self._generate_request_body(
            'download',
            obj_url=obj_url,
            env_os='windows',
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
