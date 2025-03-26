import os
import time

from anyrun.connectors import SandboxConnector


def main():
    with SandboxConnector.android(api_key) as connector:
        task_id = connector.run_url_analysis('https://any.run')
        print(f'Analysis successfully initialized. Task uuid: {task_id}')

        # Wait for the task to run
        time.sleep(10)

        for attempt, status in enumerate(connector.get_task_status(task_id), start=1):
            # You can't add more than 180 seconds
            if attempt <= 3:
                connector.add_time_to_task(task_id)
            print(status)

        report = connector.get_analysis_report(task_id, simplify=True)
        print(report if report else 'No threats were found during the analysis')

        connector.delete_task(task_id)


if __name__ == '__main__':
    api_key = 'API-KEY WuP5cpDuYA3BBm54QDDiv8xFxawSKw8dLqrfk3ax'
    main()
