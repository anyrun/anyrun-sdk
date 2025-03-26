import os

from anyrun.connectors import SandboxConnector


def main():
    with SandboxConnector.windows(api_key) as connector:
        print(connector.get_user_environment())
        print(connector.get_user_limits())
        print(connector.get_user_presets())

        print(connector.get_analysis_history())


if __name__ == '__main__':
    api_key = os.getenv('ANY_RUN_Sandbox_API_KEY')
    main()
