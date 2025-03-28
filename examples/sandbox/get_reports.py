import os

from anyrun.connectors import SandboxConnector


def main():
    with SandboxConnector.android(api_key) as connector:
        connector.download_pcap('a6cef1e0-2494-4d6d-85a9-971886f615ef', filepath='.')
        connector.get_analysis_report('a6cef1e0-2494-4d6d-85a9-971886f615ef', filepath='.', report_format='summary')
        connector.get_analysis_report('a6cef1e0-2494-4d6d-85a9-971886f615ef', filepath='.', report_format='stix')
        connector.get_analysis_report('a6cef1e0-2494-4d6d-85a9-971886f615ef', filepath='.', report_format='misp')
        connector.get_analysis_report('2b44456b-fb88-4030-ba12-74eb607b28f5', filepath='.', report_format='html')
        connector.get_analysis_report('a6cef1e0-2494-4d6d-85a9-971886f615ef', filepath='.', report_format='ioc')


if __name__ == '__main__':
    api_key = os.getenv('ANY_RUN_Sandbox_API_KEY')
    main()
