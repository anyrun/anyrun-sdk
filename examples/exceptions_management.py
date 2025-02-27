import anyrun
from anyrun.connectors import FeedsConnector


def main():
    try:
        with FeedsConnector('super_secret_api_key') as connector:
            connector.get_stix(file=False, port=False, period='month')
    except anyrun.RunTimeException as exception:
        print(f'Summary: {exception.json}')
        print(f'Status: {exception.status}')
        print(f'Status code: {exception.status_code}')
        print(f'Description: {exception.description}')
        print(exception)


if __name__ == '__main__':
    main()
