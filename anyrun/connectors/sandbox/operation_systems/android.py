from uuid import UUID
from typing import Optional, Union

import aiohttp

from anyrun.connectors.sandbox.base_connector import BaseSandboxConnector
from anyrun.utils.config import Config
from anyrun.utils.utility_functions import execute_synchronously


class AndroidConnector(BaseSandboxConnector):
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
        proxy_username: Optional[str] = None,
        proxy_password: Optional[str] = None,
        connector: Optional[aiohttp.BaseConnector] = None,
        timeout: int = Config.DEFAULT_REQUEST_TIMEOUT_IN_SECONDS,
        enable_requests: bool = False
    ) -> None:
        """
        :param api_key: ANY.RUN API-KEY in format: API-KEY <token> or Basic token in format: Basic <base64_auth>.
        :param integration: Name of the integration.
        :param trust_env: Trust environment settings for proxy configuration.
        :param verify_ssl: Enable/disable SSL verification option.
        :param proxy: Proxy url. Example: http://<host>:<port>.
        :param proxy_username: Proxy username.
        :param proxy_password: Proxy password.
        :param connector: A custom aiohttp connector.
        :param timeout: Override the session’s timeout.
        :param enable_requests: Use requests.request to make api calls. May block the event loop.
        """
        super().__init__(
            api_key,
            integration,
            trust_env,
            verify_ssl,
            proxy,
            proxy_username,
            proxy_password,
            connector,
            timeout,
            enable_requests
        )

    def run_file_analysis(
        self,
        file_content: Optional[bytes] = None,
        filename: Optional[str] = None,
        filepath: Optional[str] = None,
        env_locale: str = 'en-US',
        opt_network_connect: bool = True,
        opt_network_fakenet: bool = False,
        opt_network_tor: bool = False,
        opt_network_geo: str = 'fastest',
        opt_network_mitm: bool = False,
        opt_network_residential_proxy: bool = False,
        opt_network_residential_proxy_geo: str = 'fastest',
        opt_privacy_type: str = 'bylink',
        opt_timeout: int = 60,
        opt_automated_interactivity: bool = True,
        obj_ext_cmd: Optional[str] = None,
        user_tags: Optional[str] = None,
        task_rerun_uuid: Optional[str] = None
    ) -> Union[UUID, str]:
        """
        Initializes a new file analysis according to the specified parameters
        You can find extended documentation `here <https://any.run/api-documentation/#api-Analysis-PostAnalysis>`_
        Options: file_content and filename have higher priority then filepath option

        :param file_content: File bytes to analyse.
        :param filename: Filename with file extension.
        :param filepath: Absolute path to file. If specified, automatically process file content and filename
        :param env_locale: Operation system's language. Use locale identifier or country name (Ex: "en-US" or "Brazil").
            Case insensitive.
        :param opt_network_connect: Network connection state
        :param opt_network_fakenet: FakeNet feature status
        :param opt_network_tor: TOR using
        :param opt_network_geo: Tor geo location option. Example: US, AU
        :param opt_network_mitm: HTTPS MITM proxy option.
        :param opt_network_residential_proxy: Residential proxy using
        :param opt_network_residential_proxy_geo: Residential proxy geo location option. Example: US, AU
        :param opt_privacy_type: Privacy settings. Supports: public, bylink, owner, byteam
        :param opt_timeout: Timeout option. Size range: 10-660
        :param opt_automated_interactivity: Automated Interactivity (ML) option
        :param obj_ext_cmd: Optional command line.
        :param user_tags: Append user tags to new analysis. Only characters a-z, A-Z, 0-9, hyphen (-), and comma (,)
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
            env_locale=env_locale,
            opt_network_connect=opt_network_connect,
            opt_network_fakenet=opt_network_fakenet,
            opt_network_tor=opt_network_tor,
            opt_network_geo=opt_network_geo,
            opt_network_mitm=opt_network_mitm,
            opt_network_residential_proxy=opt_network_residential_proxy,
            opt_network_residential_proxy_geo=opt_network_residential_proxy_geo,
            opt_privacy_type=opt_privacy_type,
            opt_timeout=opt_timeout,
            opt_automated_interactivity=opt_automated_interactivity,
            obj_ext_cmd=obj_ext_cmd,
            task_rerun_uuid=task_rerun_uuid,
            user_tags=user_tags
        )

    async def run_file_analysis_async(
        self,
        file_content: Optional[bytes] = None,
        filename: Optional[str] = None,
        filepath: Optional[str] = None,
        env_locale: str = 'en-US',
        opt_network_connect: bool = True,
        opt_network_fakenet: bool = False,
        opt_network_tor: bool = False,
        opt_network_geo: str = 'fastest',
        opt_network_mitm: bool = False,
        opt_network_residential_proxy: bool = False,
        opt_network_residential_proxy_geo: str = 'fastest',
        opt_privacy_type: str = 'bylink',
        opt_timeout: int = 60,
        opt_automated_interactivity: bool = True,
        obj_ext_cmd: Optional[str] = None,
        user_tags: Optional[str] = None,
        task_rerun_uuid: Optional[str] = None
    ) -> Union[UUID, str]:
        """
        Initializes a new file analysis according to the specified parameters
        You can find extended documentation `here <https://any.run/api-documentation/#api-Analysis-PostAnalysis>`_
        Options: file_content and filename have higher priority then filepath option

        :param file_content: File bytes to analyse.
        :param filename: Filename with file extension.
        :param filepath: Absolute path to file. If specified, automatically process file content and filename
        :param env_locale: Operation system's language. Use locale identifier or country name (Ex: "en-US" or "Brazil").
            Case insensitive.
        :param opt_network_connect: Network connection state
        :param opt_network_fakenet: FakeNet feature status
        :param opt_network_tor: TOR using
        :param opt_network_geo: Tor geo location option. Example: US, AU
        :param opt_network_mitm: HTTPS MITM proxy option.
        :param opt_network_residential_proxy: Residential proxy using
        :param opt_network_residential_proxy_geo: Residential proxy geo location option. Example: US, AU
        :param opt_privacy_type: Privacy settings. Supports: public, bylink, owner, byteam
        :param opt_timeout: Timeout option. Size range: 10-660
        :param opt_automated_interactivity: Automated Interactivity (ML) option
        :param obj_ext_cmd: Optional command line.
        :param user_tags: Append user tags to new analysis. Only characters a-z, A-Z, 0-9, hyphen (-), and comma (,)
            are allowed. Max tag length: 16 characters. Max unique tags per task: 8.
        :param task_rerun_uuid: Completed task identifier. Re-runs an existent task if uuid is specified. You can re-run
            task with new parameters
        :return: Task uuid
        """
        url = f'{Config.ANY_RUN_API_URL}/analysis'
        params = {
            'env_os': 'android',
            'env_version': '14',
            'env_bitness': '64',
            'env_type': 'complete',
            'env_locale': env_locale,
            'opt_network_connect': opt_network_connect,
            'opt_network_fakenet': opt_network_fakenet,
            'opt_network_tor': opt_network_tor,
            'opt_network_geo': opt_network_geo,
            'opt_network_mitm': opt_network_mitm,
            'opt_network_residential_proxy': opt_network_residential_proxy,
            'opt_network_residential_proxy_geo': opt_network_residential_proxy_geo,
            'opt_privacy_type': opt_privacy_type,
            'opt_timeout': opt_timeout,
            'opt_automated_interactivity': opt_automated_interactivity,
            'obj_ext_startfolder': 'downloads',
            'obj_ext_cmd': obj_ext_cmd,
            'task_rerun_uuid': task_rerun_uuid,
            'user_tags': user_tags
        }

        if self._enable_requests:
            file_content, filename = await self._get_file_payload(file_content, filename, filepath)
            files = {filename: (filename, file_content)}
            response_data = await self._make_request_async('POST', url, json=params, files=files)
        else:
            body = await self._generate_multipart_request_body(
                file_content=file_content,
                filename=filename,
                filepath=filepath,
                **params
            )
            response_data = await self._make_request_async('POST', url, data=body)
        return response_data.get('data').get('taskid')

    def run_url_analysis(
        self,
        obj_url: str,
        env_locale: str = 'en-US',
        opt_network_connect: bool = True,
        opt_network_fakenet: bool = False,
        opt_network_tor: bool = False,
        opt_network_geo: str = 'fastest',
        opt_network_mitm: bool = False,
        opt_network_residential_proxy: bool = False,
        opt_network_residential_proxy_geo: str = 'fastest',
        opt_privacy_type: str = 'bylink',
        opt_timeout: int = 60,
        opt_automated_interactivity: bool = True,
        user_tags: Optional[str] = None,
        task_rerun_uuid: Optional[str] = None
    ) -> Union[UUID, str]:
        """
        Initializes a new analysis according to the specified parameters
        You can find extended documentation `here <https://any.run/api-documentation/#api-Analysis-PostAnalysis>`_

        :param obj_url: Target URL. Size range 5-512. Example: (http/https)://(your-link)
        :param env_locale: Operation system's language. Use locale identifier or country name (Ex: "en-US" or "Brazil").
            Case insensitive.
        :param opt_network_connect: Network connection state
        :param opt_network_fakenet: FakeNet feature status
        :param opt_network_tor: TOR using
        :param opt_network_geo: Tor geo location option. Example: US, AU
        :param opt_network_mitm: HTTPS MITM proxy option.
        :param opt_network_residential_proxy: Residential proxy using
        :param opt_network_residential_proxy_geo: Residential proxy geo location option. Example: US, AU
        :param opt_privacy_type: Privacy settings. Supports: public, bylink, owner, byteam
        :param opt_timeout: Timeout option. Size range: 10-660
        :param opt_automated_interactivity: Automated Interactivity (ML) option
        :param user_tags: Append user tags to new analysis. Only characters a-z, A-Z, 0-9, hyphen (-), and comma (,)
            are allowed. Max tag length: 16 characters. Max unique tags per task: 8.
        :param task_rerun_uuid: Completed task identifier. Re-runs an existent task if uuid is specified. You can re-run
            task with new parameters
        :return: Task uuid
        """
        return execute_synchronously(
            self.run_url_analysis_async,
            obj_url=obj_url,
            env_locale=env_locale,
            opt_network_connect=opt_network_connect,
            opt_network_fakenet=opt_network_fakenet,
            opt_network_tor=opt_network_tor,
            opt_network_geo=opt_network_geo,
            opt_network_mitm=opt_network_mitm,
            opt_network_residential_proxy=opt_network_residential_proxy,
            opt_network_residential_proxy_geo=opt_network_residential_proxy_geo,
            opt_privacy_type=opt_privacy_type,
            opt_timeout=opt_timeout,
            opt_automated_interactivity=opt_automated_interactivity,
            task_rerun_uuid=task_rerun_uuid,
            user_tags=user_tags
        )

    async def run_url_analysis_async(
        self,
        obj_url: str,
        env_locale: str = 'en-US',
        opt_network_connect: bool = True,
        opt_network_fakenet: bool = False,
        opt_network_tor: bool = False,
        opt_network_geo: str = 'fastest',
        opt_network_mitm: bool = False,
        opt_network_residential_proxy: bool = False,
        opt_network_residential_proxy_geo: str = 'fastest',
        opt_privacy_type: str = 'bylink',
        opt_timeout: int = 60,
        opt_automated_interactivity: bool = True,
        user_tags: Optional[str] = None,
        task_rerun_uuid: Optional[str] = None
    ) -> Union[UUID, str]:
        """
        Initializes a new analysis according to the specified parameters
        You can find extended documentation `here <https://any.run/api-documentation/#api-Analysis-PostAnalysis>`_

        :param obj_url: Target URL. Size range 5-512. Example: (http/https)://(your-link)
        :param env_locale: Operation system's language. Use locale identifier or country name (Ex: "en-US" or "Brazil").
            Case insensitive.
        :param opt_network_connect: Network connection state
        :param opt_network_fakenet: FakeNet feature status
        :param opt_network_tor: TOR using
        :param opt_network_geo: Tor geo location option. Example: US, AU
        :param opt_network_mitm: HTTPS MITM proxy option.
        :param opt_network_residential_proxy: Residential proxy using
        :param opt_network_residential_proxy_geo: Residential proxy geo location option. Example: US, AU
        :param opt_privacy_type: Privacy settings. Supports: public, bylink, owner, byteam
        :param opt_timeout: Timeout option. Size range: 10-660
        :param opt_automated_interactivity: Automated Interactivity (ML) option
        :param user_tags: Append user tags to new analysis. Only characters a-z, A-Z, 0-9, hyphen (-), and comma (,)
            are allowed. Max tag length: 16 characters. Max unique tags per task: 8.
        :param task_rerun_uuid: Completed task identifier. Re-runs an existent task if uuid is specified. You can re-run
            task with new parameters
        :return: Task uuid
        """
        url = f'{Config.ANY_RUN_API_URL}/analysis'

        body = await self._generate_request_body(
            'url',
            obj_url=obj_url,
            env_os='android',
            env_version='14',
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
            opt_privacy_type=opt_privacy_type,
            opt_timeout=opt_timeout,
            opt_automated_interactivity=opt_automated_interactivity,
            task_rerun_uuid=task_rerun_uuid,
            user_tags=user_tags
        )
        response_data = await self._make_request_async('POST', url, json=body)
        return response_data.get('data').get('taskid')

    def run_download_analysis(
        self,
        obj_url: str,
        env_locale: str = 'en-US',
        opt_network_connect: bool = True,
        opt_network_fakenet: bool = False,
        opt_network_tor: bool = False,
        opt_network_geo: str = 'fastest',
        opt_network_mitm: bool = False,
        opt_network_residential_proxy: bool = False,
        opt_network_residential_proxy_geo: str = 'fastest',
        opt_privacy_type: str = 'bylink',
        opt_timeout: int = 60,
        opt_automated_interactivity: bool = True,
        obj_ext_cmd: Optional[str] = None,
        obj_ext_useragent: Optional[str] = None,
        opt_privacy_hidesource: bool = False,
        user_tags: Optional[str] = None,
        task_rerun_uuid: Optional[str] = None
    ) -> Union[UUID, str]:
        """
        Initializes a new analysis according to the specified parameters
        You can find extended documentation `here <https://any.run/api-documentation/#api-Analysis-PostAnalysis>`_

        :param obj_url: Target URL. Size range 5-512. Example: (http/https)://(your-link)
        :param env_locale: Operation system's language. Use locale identifier or country name (Ex: "en-US" or "Brazil").
            Case insensitive.
        :param opt_network_connect: Network connection state
        :param opt_network_fakenet: FakeNet feature status
        :param opt_network_tor: TOR using
        :param opt_network_geo: Tor geo location option. Example: US, AU
        :param opt_network_mitm: HTTPS MITM proxy option.
        :param opt_network_residential_proxy: Residential proxy using
        :param opt_network_residential_proxy_geo: Residential proxy geo location option. Example: US, AU
        :param opt_privacy_type: Privacy settings. Supports: public, bylink, owner, byteam
        :param opt_timeout: Timeout option. Size range: 10-660
        :param opt_automated_interactivity: Automated Interactivity (ML) option
        :param obj_ext_cmd: Optional command line.
        :param obj_ext_useragent: User-Agent value.
        :param user_tags: Append user tags to new analysis. Only characters a-z, A-Z, 0-9, hyphen (-), and comma (,)
            are allowed. Max tag length: 16 characters. Max unique tags per task: 8.
        :param opt_privacy_hidesource: Option for hiding of source URL.
        :param task_rerun_uuid: Completed task identifier. Re-runs an existent task if uuid is specified. You can re-run
            task with new parameters
        :return: Task uuid
        """
        return execute_synchronously(
            self.run_download_analysis_async,
            obj_url=obj_url,
            env_locale=env_locale,
            opt_network_connect=opt_network_connect,
            opt_network_fakenet=opt_network_fakenet,
            opt_network_tor=opt_network_tor,
            opt_network_geo=opt_network_geo,
            opt_network_mitm=opt_network_mitm,
            opt_network_residential_proxy=opt_network_residential_proxy,
            opt_network_residential_proxy_geo=opt_network_residential_proxy_geo,
            opt_privacy_type=opt_privacy_type,
            opt_timeout=opt_timeout,
            opt_automated_interactivity=opt_automated_interactivity,
            task_rerun_uuid=task_rerun_uuid,
            obj_ext_cmd=obj_ext_cmd,
            obj_ext_useragent=obj_ext_useragent,
            opt_privacy_hidesource=opt_privacy_hidesource,
            user_tags=user_tags
        )

    async def run_download_analysis_async(
        self,
        obj_url: str,
        env_locale: str = 'en-US',
        opt_network_connect: bool = True,
        opt_network_fakenet: bool = False,
        opt_network_tor: bool = False,
        opt_network_geo: str = 'fastest',
        opt_network_mitm: bool = False,
        opt_network_residential_proxy: bool = False,
        opt_network_residential_proxy_geo: str = 'fastest',
        opt_privacy_type: str = 'bylink',
        opt_timeout: int = 60,
        opt_automated_interactivity: bool = True,
        obj_ext_cmd: Optional[str] = None,
        obj_ext_useragent: Optional[str] = None,
        opt_privacy_hidesource: bool = False,
        user_tags: Optional[str] = None,
        task_rerun_uuid: Optional[str] = None
    ) -> Union[UUID, str]:
        """
        Initializes a new analysis according to the specified parameters
        You can find extended documentation `here <https://any.run/api-documentation/#api-Analysis-PostAnalysis>`_

        :param obj_url: Target URL. Size range 5-512. Example: (http/https)://(your-link)
        :param env_locale: Operation system's language. Use locale identifier or country name (Ex: "en-US" or "Brazil").
            Case insensitive.
        :param opt_network_connect: Network connection state
        :param opt_network_fakenet: FakeNet feature status
        :param opt_network_tor: TOR using
        :param opt_network_geo: Tor geo location option. Example: US, AU
        :param opt_network_mitm: HTTPS MITM proxy option.
        :param opt_network_residential_proxy: Residential proxy using
        :param opt_network_residential_proxy_geo: Residential proxy geo location option. Example: US, AU
        :param opt_privacy_type: Privacy settings. Supports: public, bylink, owner, byteam
        :param opt_timeout: Timeout option. Size range: 10-660
        :param opt_automated_interactivity: Automated Interactivity (ML) option
        :param obj_ext_cmd: Optional command line.
        :param obj_ext_useragent: User-Agent value.
        :param opt_privacy_hidesource: Option for hiding of source URL.
        :param user_tags: Append user tags to new analysis. Only characters a-z, A-Z, 0-9, hyphen (-), and comma (,)
            are allowed. Max tag length: 16 characters. Max unique tags per task: 8.
        :param task_rerun_uuid: Completed task identifier. Re-runs an existent task if uuid is specified. You can re-run
            task with new parameters
        :return: Task uuid
        """
        url = f'{Config.ANY_RUN_API_URL}/analysis'

        body = await self._generate_request_body(
            'download',
            obj_url=obj_url,
            env_os='android',
            env_version='14',
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
            opt_privacy_type=opt_privacy_type,
            opt_timeout=opt_timeout,
            opt_automated_interactivity=opt_automated_interactivity,
            obj_ext_startfolder='downloads',
            task_rerun_uuid=task_rerun_uuid,
            obj_ext_cmd=obj_ext_cmd,
            obj_ext_useragent=obj_ext_useragent,
            opt_privacy_hidesource=opt_privacy_hidesource,
            user_tags=user_tags
        )

        response_data = await self._make_request_async('POST', url, json=body)
        return response_data.get('data').get('taskid')
