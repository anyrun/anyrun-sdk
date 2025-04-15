import os
import asyncio
from pprint import pprint

from anyrun.connectors import SandboxConnector


async def main():
    async with SandboxConnector.linux(api_key) as connector:
        task_id = await connector.run_file_analysis_async('suspicious_file.txt', opt_network_mitm=True)
        print(f'Analysis successfully initialized. Task uuid: {task_id}')

        async for status in connector.get_task_status_async(task_id):
            print(status)

        report = await connector.get_analysis_report_async(task_id)
        pprint(report)

        await connector.delete_task_async(task_id)


if __name__ == '__main__':
    api_key = os.getenv('ANY_RUN_Sandbox_API_KEY')
    asyncio.run(main())
