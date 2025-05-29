from typing import Optional
from datetime import datetime, timedelta

import aiohttp

from anyrun.connectors.base_connector import AnyRunConnector

from anyrun.utils.config import Config
from anyrun.utils.utility_functions import execute_synchronously


class LookupConnector(AnyRunConnector):
    """
    Provides ANY.RUN TI Lookup endpoint management.
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
        :param api_key: ANY.RUN API Key in format: API-KEY <api_key>
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
        url = f"{Config.ANY_RUN_API_URL}/intelligence/keycheck"
        await self._make_request_async('GET', url)
        return {'status': 'ok', 'description': 'Successful credential verification'}

    def get_intelligence(
            self,
            start_date: Optional[str] = (datetime.now() - timedelta(days=180)).date().strftime('%Y-%m-%d'),
            end_date: Optional[str] = datetime.now().date().strftime('%Y-%m-%d'),
            lookup_depth: Optional[int] = None,
            query: Optional[str] = None,
            threat_name: Optional[str] = None,
            threat_level: Optional[str] = None,
            task_type: Optional[str] = None,
            submission_country: Optional[str] = None,
            os: Optional[str] = None,
            os_software_set: Optional[str] = None,
            os_bit_version: Optional[str] = None,
            registry_key: Optional[str] = None,
            registry_name: Optional[str] = None,
            registry_value: Optional[str] = None,
            module_image_path: Optional[str] = None,
            rule_threat_level: Optional[str] = None,
            rule_name: Optional[str] = None,
            mitre: Optional[str] = None,
            image_path: Optional[str] = None,
            command_line: Optional[str] = None,
            injected_flag: Optional[str] = None,
            destination_ip: Optional[str] = None,
            destination_port: Optional[str] = None,
            destination_ip_asn: Optional[str] = None,
            destination_ip_geo: Optional[str] = None,
            domain_name: Optional[str] = None,
            ja3: Optional[str] = None,
            ja3s: Optional[str] = None,
            jarm : Optional[str] = None,
            file_path: Optional[str] = None,
            file_event_path: Optional[str] = None,
            file_extension: Optional[str] = None,
            sha256: Optional[str] = None,
            sha1: Optional[str] = None,
            md5: Optional[str] = None,
            suricata_class: Optional[str] = None,
            suricata_message: Optional[str] = None,
            suricata_threat_level: Optional[str] = None,
            suricata_id: Optional[str] = None,
            sync_object_name: Optional[str] = None,
            sync_object_type: Optional[str] = None,
            sync_object_operation: Optional[str] = None,
            url: Optional[str] = None,
            http_request_content_type: Optional[str] = None,
            http_response_content_type: Optional[str] = None,
            http_request_file_type: Optional[str] = None,
            http_response_file_type: Optional[str] = None
    ) -> dict:
        """
        Returns Lookup object according to the specified query parameters.
        Supports two ways to build a request query:

        * According to specified keyword arguments. All conditions are combined using the AND operator.
        * According to specified raw query. All conditions are combined using specified operators.

        You cannot use both methods at the same time. If a query and some other filter parameters are specified,
        the query parameter will have higher priority

        :param start_date: Indicating the beginning of the period for which events is requested. Format: YYYY-MM-DD
        :param end_date: Indicating the end of the period for which events is requested. Format: YYYY-MM-DD
        :param lookup_depth: Specify the number of days from the current date for which you want to lookup
        :param query: Raw query with necessary filters. Supports condition concatenation with AND, OR, NOT and
            Parentheses ()
        :param threat_name: The name of a particular threat: malware family, threat type, etc., as identified by the
            sandbox. Example: "Phishing"
        :param threat_level: A verdict on the threat level of the sample. Supports: **suspicious, malicious, info**
        :param task_type: The type of the sample submitted to the sandbox. Supports: **File, URL**
        :param submission_country: The country from which the threat sample was submitted. Example: "es"
        :param os: The specific version of Windows used in the environment. Supports: **Windows 7, Windows 10,
            Windows 11**
        :param os_software_set: The software package of applications installed on the OS. Supports: **clean, office,
            complete**
        :param os_bit_version: The bitness of the operating system. Supports: **32, 64**
        :param registry_key: The specific key within the registry hive where the modification occurred. Please note:
            when entering registry keys, use a double backslash (\) to escape the single backslash. Example:
            "Windows\\CurrentVersion\\RunOnce"
        :param registry_name: The name of the Windows Registry key field. Example: "browseinplace"
        :param registry_value: The value of the Windows Registry key. Example: "Internet Explorer\iexplore.exe"
        :param module_image_path: The full path to the module’s image file, the location on the disk where the module’s
            executable is stored. Example: "SysWOW64\\cryptbase.dll"
        :param rule_threat_level: The threat level assigned to a particular event. Supports: **suspicious, malicious,
            info**
        :param rule_name: The name of the detection rule. Example: "Executable content was dropped or overwritten"
        :param mitre: Techniques used by the malware according to the MITRE ATT&CK classification. Example: "T1071"
        :param image_path: Full path to process image. Example: "System32\\conhost.exe"
        :param command_line: Full command line that initiated the process. Example:
            "PDQConnectAgent\\pdq-connect-agent.exe –service"
        :param injected_flag: Indication of whether a process has been injected. Supports: **"true", "false"**
        :param destination_ip: The IP address of the network connection that was established or attempted. Example:
            "147.185.221.22"
        :param destination_port: The network port through which the connection was established. Example: "49760"
        :param destination_ip_asn: Detected ASN. Example: "akamai-as"
        :param destination_ip_geo: Two-letter country or region code of the detected IP geolocation. Example: "ae"
        :param domain_name: The domain name that was recorded during the threat execution in a sandbox. Example:
            "tventyvd20sb.top"
        :param ja3: Types of TLS fingerprints that can indicate certain threats.
        :param ja3s: Types of TLS fingerprints that can indicate certain threats.
        :param jarm: Types of TLS fingerprints that can indicate certain threats.
        :param file_path: The full path to the file on the system.
        :param file_event_path: The path of a file associated with a file event.
        :param file_extension: The extension that indicates the file type.
        :param sha256: Hash values relating to a file.
        :param sha1: Hash values relating to a file.
        :param md5: Hash values relating to a file.
        :param suricata_class: The category assigned to the threat by Suricata based on its characteristics. Example:
            "a network trojan was detected"
        :param suricata_message: The description of the threat according to Suricata. Example:
            "ET INFO 404/Snake/Matiex Keylogger Style External IP Check"
        :param suricata_threat_level: The verdict on the threat according to Suricata based on its potential impact.
            Supports: **suspicious, malicious, info**
        :param suricata_id: The unique identifier of the Suricata rule: Example: "2044767"
        :param sync_object_name: The name or identifier of the synchronization object used. Example: "rmc"
        :param sync_object_type: The type of synchronization object used. Example: "mutex"
        :param sync_object_operation: The operation performed on the synchronization object. Example: "create"
        :param url: The URL called by the process. Example: "http://192.168.37.128:8880/zv8u"
        :param http_request_content_type: The content type of the HTTP request sent to the server. Example:
            "application/json"
        :param http_response_content_type: The content type of the HTTP response received from the server. Example:
            "text/html"
        :param http_request_file_type: The file type of the file being uploaded in the HTTP request. Example:
            "binary"
        :param http_response_file_type: The file type of the file being downloaded in the HTTP response. Example:
            "binary"
        :return: API response in **json** format
        """
        return execute_synchronously(
            self.get_intelligence_async,
            start_date=start_date,
            end_date=end_date,
            lookup_depth=lookup_depth,
            query=query,
            threat_name=threat_name,
            threat_level=threat_level,
            task_type=task_type,
            submission_country=submission_country,
            os=os,
            os_software_set=os_software_set,
            os_bit_version=os_bit_version,
            registry_key=registry_key,
            registry_name=registry_name,
            registry_value=registry_value,
            module_image_path=module_image_path,
            rule_threat_level=rule_threat_level,
            rule_name=rule_name,
            mitre=mitre,
            image_path=image_path,
            command_line=command_line,
            injected_flag=injected_flag,
            destination_ip=destination_ip,
            destination_port=destination_port,
            destination_ip_asn=destination_ip_asn,
            destination_ip_geo=destination_ip_geo,
            domain_name=domain_name,
            ja3=ja3,
            ja3s=ja3s,
            jarm=jarm,
            file_path=file_path,
            file_event_path=file_event_path,
            file_extension=file_extension,
            sha256=sha256,
            sha1=sha1,
            md5=md5,
            suricata_class=suricata_class,
            suricata_message=suricata_message,
            suricata_threat_level=suricata_threat_level,
            suricata_id=suricata_id,
            sync_object_name=sync_object_name,
            sync_object_type=sync_object_type,
            sync_object_operation=sync_object_operation,
            url=url,
            http_request_content_type=http_request_content_type,
            http_response_content_type=http_response_content_type,
            http_request_file_type=http_request_file_type,
            http_response_file_type=http_response_file_type
        )

    async def get_intelligence_async(
            self,
            start_date: Optional[str] = (datetime.now() - timedelta(days=180)).date().strftime('%Y-%m-%d'),
            end_date: Optional[str] = datetime.now().date().strftime('%Y-%m-%d'),
            lookup_depth: Optional[int] = None,
            query: Optional[str] = None,
            threat_name: Optional[str] = None,
            threat_level: Optional[str] = None,
            task_type: Optional[str] = None,
            submission_country: Optional[str] = None,
            os: Optional[str] = None,
            os_software_set: Optional[str] = None,
            os_bit_version: Optional[str] = None,
            registry_key: Optional[str] = None,
            registry_name: Optional[str] = None,
            registry_value: Optional[str] = None,
            module_image_path: Optional[str] = None,
            rule_threat_level: Optional[str] = None,
            rule_name: Optional[str] = None,
            mitre: Optional[str] = None,
            image_path: Optional[str] = None,
            command_line: Optional[str] = None,
            injected_flag: Optional[str] = None,
            destination_ip: Optional[str] = None,
            destination_port: Optional[str] = None,
            destination_ip_asn: Optional[str] = None,
            destination_ip_geo: Optional[str] = None,
            domain_name: Optional[str] = None,
            ja3: Optional[str] = None,
            ja3s: Optional[str] = None,
            jarm : Optional[str] = None,
            file_path: Optional[str] = None,
            file_event_path: Optional[str] = None,
            file_extension: Optional[str] = None,
            sha256: Optional[str] = None,
            sha1: Optional[str] = None,
            md5: Optional[str] = None,
            suricata_class: Optional[str] = None,
            suricata_message: Optional[str] = None,
            suricata_threat_level: Optional[str] = None,
            suricata_id: Optional[str] = None,
            sync_object_name: Optional[str] = None,
            sync_object_type: Optional[str] = None,
            sync_object_operation: Optional[str] = None,
            url: Optional[str] = None,
            http_request_content_type: Optional[str] = None,
            http_response_content_type: Optional[str] = None,
            http_request_file_type: Optional[str] = None,
            http_response_file_type: Optional[str] = None
    ) -> dict:
        """
        Returns Lookup object according to the specified query parameters.
        Supports two ways to build a request query:

        * According to specified keyword arguments. All conditions are combined using the AND operator.
        * According to specified raw query. All conditions are combined using specified operators.

        You cannot use both methods at the same time. If a query and some other filter parameters are specified,
        the query parameter will have higher priority

        :param start_date: Indicating the beginning of the period for which events is requested. Format: YYYY-MM-DD
        :param end_date: Indicating the end of the period for which events is requested. Format: YYYY-MM-DD
        :param lookup_depth: Specify the number of days from the current date for which you want to lookup
        :param query: Raw query with necessary filters. Supports condition concatenation with AND, OR, NOT and
            Parentheses ()
        :param threat_name: The name of a particular threat: malware family, threat type, etc., as identified by the
            sandbox. Example: "Phishing"
        :param threat_level: A verdict on the threat level of the sample. Supports: **suspicious, malicious, info**
        :param task_type: The type of the sample submitted to the sandbox. Supports: **File, URL**
        :param submission_country: The country from which the threat sample was submitted. Example: "es"
        :param os: The specific version of Windows used in the environment. Supports: **Windows 7, Windows 10,
            Windows 11**
        :param os_software_set: The software package of applications installed on the OS. Supports: **clean, office,
            complete**
        :param os_bit_version: The bitness of the operating system. Supports: **32, 64**
        :param registry_key: The specific key within the registry hive where the modification occurred. Please note:
            when entering registry keys, use a double backslash (\) to escape the single backslash. Example:
            "Windows\\CurrentVersion\\RunOnce"
        :param registry_name: The name of the Windows Registry key field. Example: "browseinplace"
        :param registry_value: The value of the Windows Registry key. Example: "Internet Explorer\iexplore.exe"
        :param module_image_path: The full path to the module’s image file, the location on the disk where the module’s
            executable is stored. Example: "SysWOW64\\cryptbase.dll"
        :param rule_threat_level: The threat level assigned to a particular event. Supports: **suspicious, malicious,
            info**
        :param rule_name: The name of the detection rule. Example: "Executable content was dropped or overwritten"
        :param mitre: Techniques used by the malware according to the MITRE ATT&CK classification. Example: "T1071"
        :param image_path: Full path to process image. Example: "System32\\conhost.exe"
        :param command_line: Full command line that initiated the process. Example:
            "PDQConnectAgent\\pdq-connect-agent.exe –service"
        :param injected_flag: Indication of whether a process has been injected. Supports: **"true", "false"**
        :param destination_ip: The IP address of the network connection that was established or attempted. Example:
            "147.185.221.22"
        :param destination_port: The network port through which the connection was established. Example: "49760"
        :param destination_ip_asn: Detected ASN. Example: "akamai-as"
        :param destination_ip_geo: Two-letter country or region code of the detected IP geolocation. Example: "ae"
        :param domain_name: The domain name that was recorded during the threat execution in a sandbox. Example:
            "tventyvd20sb.top"
        :param ja3: Types of TLS fingerprints that can indicate certain threats.
        :param ja3s: Types of TLS fingerprints that can indicate certain threats.
        :param jarm: Types of TLS fingerprints that can indicate certain threats.
        :param file_path: The full path to the file on the system.
        :param file_event_path: The path of a file associated with a file event.
        :param file_extension: The extension that indicates the file type.
        :param sha256: Hash values relating to a file.
        :param sha1: Hash values relating to a file.
        :param md5: Hash values relating to a file.
        :param suricata_class: The category assigned to the threat by Suricata based on its characteristics. Example:
            "a network trojan was detected"
        :param suricata_message: The description of the threat according to Suricata. Example:
            "ET INFO 404/Snake/Matiex Keylogger Style External IP Check"
        :param suricata_threat_level: The verdict on the threat according to Suricata based on its potential impact.
            Supports: **suspicious, malicious, info**
        :param suricata_id: The unique identifier of the Suricata rule: Example: "2044767"
        :param sync_object_name: The name or identifier of the synchronization object used. Example: "rmc"
        :param sync_object_type: The type of synchronization object used. Example: "mutex"
        :param sync_object_operation: The operation performed on the synchronization object. Example: "create"
        :param url: The URL called by the process. Example: (http/https)://(your-link)
        :param http_request_content_type: The content type of the HTTP request sent to the server. Example:
            "application/json"
        :param http_response_content_type: The content type of the HTTP response received from the server. Example:
            "text/html"
        :param http_request_file_type: The file type of the file being uploaded in the HTTP request. Example:
            "binary"
        :param http_response_file_type: The file type of the file being downloaded in the HTTP response. Example:
            "binary"
        :return: API response in **json** format
        """
        body = await self._generate_request_body(
            (datetime.now() - timedelta(days=lookup_depth)).date().strftime('%Y-%m-%d') if lookup_depth else start_date,
            end_date,
            query,
            {
                'threatName': threat_name,
                'submissionCountry': submission_country,
                'taskType': task_type,
                'threatLevel': threat_level,
                'registryKey': registry_key,
                'registryName': registry_name,
                'registryValue': registry_value,
                'os': os,
                'osSoftwareSet': os_software_set,
                'osBitVersion': os_bit_version,
                'ruleName': rule_name,
                'ruleThreatLevel': rule_threat_level,
                'MITRE': mitre,
                'moduleImagePath': module_image_path,
                'domainName': domain_name,
                'destinationPort': destination_port,
                'destinationIP': destination_ip,
                'destinationIpAsn': destination_ip_asn,
                'destinationIPgeo': destination_ip_geo,
                'ja3': ja3,
                'ja3s': ja3s,
                'jarm': jarm,
                'imagePath': image_path,
                'commandLine': command_line,
                'injectedFlag': injected_flag,
                'suricataMessage': suricata_message,
                'suricataClass': suricata_class,
                'suricataThreatLevel': suricata_threat_level,
                'suricataID': suricata_id,
                'filePath': file_path,
                'fileEventPath': file_event_path,
                'fileExtension': file_extension,
                'sha256': sha256,
                'sha1': sha1,
                'md5': md5,
                'syncObjectName': sync_object_name,
                'syncObjectType': sync_object_type,
                'syncObjectOperation': sync_object_operation,
                'URL': url,
                'httpRequestContentType': http_request_content_type,
                'httpResponseContentType': http_response_content_type,
                'httpRequestFileType': http_request_file_type,
                'httpResponseFileType': http_response_file_type
            }
        )
        url = f'{Config.ANY_RUN_API_URL}/intelligence/search'
        response_data = await self._make_request_async('POST', url, json=body)
        return response_data

    async def _generate_request_body(
            self,
            start_date: Optional[str],
            end_date: Optional[str],
            query: Optional[str],
            params: dict[str, str]
    ) -> dict[str, str]:
        """
        Builds complete request body according to specified parameters

        :param start_date: Indicating the beginning of the period for which events is requested.
        :param end_date: Indicating the end of the period for which events is requested.
        :param query: Raw query with necessary filters.
        :param params: Dictionary with filter parameters.
        :return:
        """
        body = {'query': query if query else await self._generate_query(params)}
        body = await self._add_time_ranges(body, start_date, end_date)
        return body

    @staticmethod
    async def _generate_query(params: dict[str, str]) -> str:
        """
        Generates filter query using specified parameters

        :param params: Dictionary with filter parameters.
        :return: Complete query
        """
        return ' AND '.join(f'{param}:"{value}"' for param, value in params.items() if value)

    @staticmethod
    async def _add_time_ranges(
            body: dict[str, str],
            start_date: Optional[str],
            end_date: Optional[str]
    ) -> dict[str, str]:
        """
        Checks if time range parameters specified. If specified, appends them to request body

        :param body: Request body
        :param start_date: Indicating the beginning of the period for which events is requested.
        :param end_date: Indicating the end of the period for which events is requested.
        :return: Updated request body
        """
        if start_date:
            body['startDate'] = start_date

        if end_date:
            body['endDate'] = end_date

        return body
