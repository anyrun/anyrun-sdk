<p align="center">
    <a href="#readme">
        <img alt="ANY.RUN logo" src="static/logo.svg">
    </a>
</p>

______________________________________________________________________

# ANY.RUN SDK
This is the official Python client library for ANY.RUN.  
With this library you can interact with the ANY.RUN REST API and automate your workflow quickly and efficiently.

Available features:

* Automate ANY.RUN Threat Intelligence Feeds management.  
  Supports the following feed formats:
  * MISP 
  * STIX
  * Network iocs

* Built-in objects iterator
* Synchronous and asynchronous interface

# The library public interface overview

```python
import os
from pprint import pprint

from anyrun.connectors.threat_intelligence import FeedsConnector


def main():
    # Initialize the connector object
    connector = FeedsConnector(api_key)
    
    # Process request to ANY.RUN feeds endpoint
    feeds = connector.get_stix(url=False, period='month', limit=500)
    pprint(feeds)


if __name__ == '__main__':
    # Setup ANY.RUN api key
    api_key = os.getenv('ANY_RUN_FEEDS_API_KEY')
    main()
```
You can find additional usage examples [here](https://github.com/anyrun/anyrun-sdk/examples)

#  Installation Guide

#### You can install the SDK using pip or any other package manager
```console
$ pip3 install anyrun-sdk
```

#### Also, you can install the SDK manually using setup.py module
```console
$ git clone git@github.com:anyrun/anyrun-sdk.git
$ cd anyrun-sdk
$ python -m pip install .
```


# Contribution Guide

There are a several conventions you must follow to add source code to the project

#### 1. Clone project repository using one of the following ways
```console
$ git clone git@github.com:anyrun/anyrun-sdk.git
$ git clone https://github.com/anyrun/anyrun-sdk.git
```

#### 2. Jump into the project directory
```console
$ cd anyrun-sdk
```

#### 4. Create a new local branch
```console
$ git checkout -b <branch_title>

Branch title template: feature/public/[TaskShortDescription]
```
* **TaskShortDescription** - Feature name. Includes only lower case words separated by dashes

#### 5. Commit your changes
```console
$ git add .
$ git commit -m <commit_title>

Commit title template: [ImpactType]([ImpactScope]): [CommitChanges]
```
* **ImpactType** 
  * feat - To implement a new feature
  * fix - To fix some bugs
  * tests - To add some tests
* **ImpactScope** - The part of the project in free form that is affected by the commit 
  * general - To add global changes
  * logs - To add logs changes
  * and other...

* **CommitChanges** - The main changes. Includes only lower case words separated by spaces. 
Multiple changes could be written separated by commas

#### 6. Open a new pull request

# Running tests

#### 1. Jump into the project directory
```console
$ cd anyrun-sdk
```

#### 2. Install dev requirements
```console
$ python -m pip install -e '.[dev]'
```

#### 3. Run tests
```console
$ pytest tests
```

# Backward Compatibility

The SDK supports Python 3.9 and higher
