import os
import asyncio
from pprint import pprint

from anyrun.connectors import SandboxConnector


async def main():
    async with SandboxConnector.linux(api_key) as connector:
        analysis_id = await connector.run_file_analysis_async(filepath='suspicious_file.txt')
        print(f'Analysis successfully initialized. Analysis uuid: {analysis_id}')

        async for status in connector.get_task_status_async(analysis_id):
            print(status)

        report = await connector.get_analysis_report_async(analysis_id)
        pprint(report)

        await connector.delete_task_async(analysis_id)


if __name__ == '__main__':
    api_key = os.getenv('ANY_RUN_Sandbox_API_KEY')
    asyncio.run(main())
