import base64
import json
import os

from anyrun.connectors.sandbox.base_connector import BaseSandboxConnector

def main():
    with BaseSandboxConnector(api_key) as connector:
        analysis_uuid = 'c7f88546-cd8d-47ba-8159-7b7a8ef28a52'
        # Reports management
        connector.get_analysis_report(analysis_uuid, filepath='.', report_format='stix')
        connector.get_analysis_report(analysis_uuid, filepath='.', report_format='misp')
        connector.get_analysis_report(analysis_uuid, filepath='.', report_format='html')
        connector.get_analysis_report(analysis_uuid, filepath='.', report_format='json')

        iocs = connector.get_analysis_report(analysis_uuid, report_format='ioc', ioc_reputation='malicious')
        print(iocs)

        print(connector.get_analysis_verdict(analysis_uuid))

        # File samples management
        connector.download_pcap(analysis_uuid, filepath='.')
        connector.download_file_sample(analysis_uuid, filepath='.')

        # Utils
        print(connector.get_user_environment())
        print(connector.get_user_limits())
        print(connector.get_user_presets())
        print(connector.get_analysis_history())

if __name__ == '__main__':
    api_key = os.getenv('ANY_RUN_Sandbox_API_KEY')
    main()
