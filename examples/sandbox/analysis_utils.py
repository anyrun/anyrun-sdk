import os

from anyrun.connectors.sandbox.base_connector import BaseSandboxConnector

def main():
    with BaseSandboxConnector(api_key) as connector:
        # Reports management
        connector.get_analysis_report('4b3dc852-3535-48f9-bf28-f95a27da2415', filepath='.', report_format='stix')
        connector.get_analysis_report('4b3dc852-3535-48f9-bf28-f95a27da2415', filepath='.', report_format='misp')
        connector.get_analysis_report('4b3dc852-3535-48f9-bf28-f95a27da2415', filepath='.', report_format='html')
        connector.get_analysis_report('4b3dc852-3535-48f9-bf28-f95a27da2415', filepath='.', report_format='summary')

        iocs = connector.get_analysis_report('4b3dc852-3535-48f9-bf28-f95a27da2415', report_format='ioc', ioc_reputation='malicious')
        print(iocs)

        print(connector.get_analysis_verdict('4b3dc852-3535-48f9-bf28-f95a27da2415'))
        # File samples management
        connector.download_pcap('4b3dc852-3535-48f9-bf28-f95a27da2415', filepath='.')
        connector.download_file_sample('4b3dc852-3535-48f9-bf28-f95a27da2415', filepath='.')
        # Utils
        print(connector.get_user_environment())
        print(connector.get_user_limits())
        print(connector.get_user_presets())
        print(connector.get_analysis_history())

if __name__ == '__main__':
    api_key = os.getenv('ANY_RUN_Sandbox_API_KEY')
    main()
