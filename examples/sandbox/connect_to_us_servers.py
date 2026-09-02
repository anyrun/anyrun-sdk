import os
from pprint import pprint

from anyrun.connectors import SandboxConnector


def main():
    # Use the root_url parameter to route sandbox requests to the ANY.RUN US servers
    with SandboxConnector.windows(api_key, root_url='anyrun.us') as connector:
        analysis_id = connector.run_url_analysis('https://any.run')
        print(f'Analysis successfully initialized. Analysis uuid: {analysis_id}')

        for status in connector.get_task_status(analysis_id):
            print(status)

        report = connector.get_analysis_report(analysis_id)
        pprint(report)

        connector.delete_task(analysis_id)


if __name__ == '__main__':
    api_key = os.getenv('ANY_RUN_Sandbox_API_KEY')
    main()
