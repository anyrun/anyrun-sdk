import os
from pprint import pprint

from anyrun import RunTimeException
from anyrun.connectors import SandboxConnector


def follow_queued_task():
    with SandboxConnector.windows(api_key) as connector:
        # If all parallel slots are busy, the task waits in the queue instead of failing.
        # In this case the method returns a queue task id, otherwise a task uuid
        task_id = connector.run_url_analysis('https://any.run', queue_parallel=True)
        print(f'Analysis successfully initialized. Task id: {task_id}')

        # The tasks waiting in the queue. A task appears in the list a few seconds after it was queued
        for queued_task in connector.get_queued_tasks():
            print(f'Queued: {queued_task["queueTaskId"]}, tasks ahead: {queued_task["tasksAhead"]}, '
                  f'reason: {queued_task["queueLastReason"]}')

        # The queue task id can be used to follow the task. Status is QUEUED until the task starts
        task_uuid = task_id
        for status in connector.get_task_status(task_id):
            print(status)

            if status['task_uuid']:
                task_uuid = status['task_uuid']

        # Reports require the real task uuid
        report = connector.get_analysis_report(task_uuid)
        pprint(report)

        connector.delete_task(task_uuid)


def remove_queued_task():
    with SandboxConnector.windows(api_key) as connector:
        queue_id = connector.run_url_analysis('https://any.run', queue_parallel=True)

        try:
            connector.remove_task_from_queue(queue_id)
            print(f'The task {queue_id} was removed from the queue')
        except RunTimeException as exception:
            # The task is not queued: it has already started, so stop it instead
            print(exception)
            connector.stop_task(queue_id)


if __name__ == '__main__':
    api_key = os.getenv('ANY_RUN_Sandbox_API_KEY')
    follow_queued_task()
    remove_queued_task()
