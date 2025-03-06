import os

from anyrun.connectors import SandBoxConnector


def main():
    with SandBoxConnector(api_key) as connector:
        task_id = connector.run_url_analysis('https://any.run')
        print(f'Analysis successfully initialized. Task uuid: {task_id}')

        for status in connector.get_task_status(task_id):
            print(status)

        report = connector.get_analysis_report(task_id, simplify=True)
        print(report if report else 'No threats were found during the analysis')

        connector.delete_task(task_id)


if __name__ == '__main__':
    api_key = os.getenv('ANY_RUN_Sandbox_API_KEY')
    main()
