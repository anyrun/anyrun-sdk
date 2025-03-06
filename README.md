<p align="center">
    <a href="#readme">
        <img alt="ANY.RUN logo" src="https://raw.githubusercontent.com/anyrun/anyrun-sdk/b3dfde1d3aa018d0a1c3b5d0fa8aaa652e80d883/static/logo.svg">
    </a>
</p>

______________________________________________________________________

# ANY.RUN SDK
This is the official Python client library for [ANY.RUN](https://any.run/).  
With this library you can interact with the ANY.RUN REST API and automate your workflow quickly and efficiently.

# Available features

### TI Feeds API  
  Supports the following feed formats for search:
  * MISP 
  * STIX
  * Network iocs 

### TI Lookup API
  * Look up URLs and file hashes
  * Get threat intelligence data
  * Check indicators of compromise

### TI YARA API
  * Search for new IOC using YARA rules
  * Monitor Search progress in real-time
  * Get detailed analysis results

### Sandbox API
  * Submit files and URLs for analysis
  * Monitor analysis progress in real-time
  * Get detailed analysis results
  * Manage analysis tasks 

### Other features
* Built-in objects iterator
* Built-in exception handling
* The same synchronous and asynchronous interface
* Supports Python 3.9-3.13

# The library public interface overview

```python
import os

from anyrun.connectors import SandBoxConnector


def main():
    with SandBoxConnector(api_key) as connector:
        # Initialize the url analysis
        task_id = connector.run_url_analysis('https://any.run')
        print(f'Analysis successfully initialized. Task uuid: {task_id}')
        
        # View analysis status in real time
        for status in connector.get_task_status(task_id):
            print(status)
        
        # Get report results
        report = connector.get_analysis_report(task_id, simplify=True)
        print(report if report else 'No threats were found during the analysis')
        
        # Remove the task from history
        connector.delete_task(task_id)


if __name__ == '__main__':
    # Setup ANY.RUN api key
    api_key = os.getenv('ANY_RUN_Sandbox_API_KEY')
    main()

```
You can find additional usage examples [here](https://github.com/anyrun/anyrun-sdk/tree/main/examples)

#  Installation Guide

#### You can install the SDK using pip or any other package manager
```console
$ pip install anyrun-sdk
```

#### Also, you can install the SDK manually using pyproject.toml
```console
$ git clone git@github.com:anyrun/anyrun-sdk.git
$ cd anyrun-sdk
$ python -m pip install .
```

# Contributing
We welcome contributions! Please see our [Contributing Guide](https://github.com/anyrun/anyrun-sdk/blob/main/CONTRIBUTING.md) for details.

# Useful links

[TI Lookup query Guide](https://intelligence.any.run/TI_Lookup_Query_Guide_v4.pdf)  
[ANY.RUN API documentation](https://any.run/api-documentation/#api-Request-Request)
