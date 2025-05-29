<p align="center">
    <a href="#readme">
        <img alt="ANY.RUN logo" src="https://raw.githubusercontent.com/anyrun/anyrun-sdk/b3dfde1d3aa018d0a1c3b5d0fa8aaa652e80d883/static/logo.svg">
    </a>
</p>

______________________________________________________________________

# ANY.RUN SDK
This is the official Python client library for [ANY.RUN](https://app.any.run/?utm_source=sdk_projects&utm_medium=integration&utm_campaign=appanyrun), supporting the cybersecurity solutions like the Interactive Sandbox, TI Lookup, and TI Feeds.  
With this library you can interact with the ANY.RUN REST API and automate your workflow quickly and efficiently. 

# Available features

* Built-in objects iterator and exception handling 
* Synchronous and asynchronous interface 
* Python 3.9-3.13 support 

### Sandbox API
[ANY.RUN Sandbox](https://app.any.run/?utm_source=sdk_projects&utm_medium=integration&utm_campaign=appanyrun) is an online interactive sandbox for malware analysis, a tool for detection, monitoring, and research of cyber threats in real time. 

  * Submit files and URLs for analysis
  * Monitor analysis progress in real-time
  * Get detailed reports 
  * Manage the tasks 

### TI Lookup API and YARA Search 
TI Lookup is a [searchable database](https://intelligence.any.run/?utm_source=sdk_projects&utm_medium=integration&utm_campaign=intelligence-lookup) 
of IOCs, IOAs, IOBs, and events for threat hunting and a [service](https://intelligence.any.run/analysis/yara/?utm_source=sdk_projects&utm_medium=integration&utm_campaign=intelligence-yara)
for browsing malicious files by their content. 
Perform deep searches, look up threats online, and enrich your security solutions. 

  * Look up URLs and file hashes 
  * Search for IOCs using YARA rules 
  * Get threat intelligence data 
  * Monitor search progress in real time 
  * Get detailed analysis results 

### TI Feeds API  
[Threat Intelligence Feeds](https://intelligence.any.run/feeds/?utm_source=sdk_projects&utm_medium=integration&utm_campaign=intelligence-feeds) 
provide data on the known indicators of compromise: malicious IPs, URLs, Domains
Supports the following feed formats: 
  * MISP 
  * [TAXII](https://oasis-open.github.io/cti-documentation/taxii/intro.html) STIX
  * Network IOCs 

# The library public interface overview

```python
import os
from pprint import pprint

from anyrun.connectors import SandboxConnector


def main():
    with SandboxConnector.android(api_key) as connector:
        # Initialize the url analysis
        task_id = connector.run_url_analysis('https://any.run')
        print(f'Analysis successfully initialized. Task uuid: {task_id}')
        
        # View analysis status in real time
        for status in connector.get_task_status(task_id):
            print(status)
        
        # Get report results
        report = connector.get_analysis_report(task_id)
        pprint(report)
        
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

# Contact us 

Support, sales, and trial inquiries – support@any.run  
Public relations and partnerships – pr@any.run 