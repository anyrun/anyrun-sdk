# Contribution Guide

Thanks everyone for contributing to the project. Let's make the SDK better together!  
If you encounter any problem or want to discuss some improvements of the SDK
contact us by mail **anyrun-integrations@any.run** or open a new issue or pull request.

## Code of Conduct

This project and everyone participating in it is governed by our Code of Conduct. By participating, you are expected to uphold this code.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the issue list as you might find out that you don't need to create one. When you are creating a bug report, please include as many details as possible:

* Use a clear and descriptive title
* Describe the exact steps which reproduce the problem
* Provide specific examples to demonstrate the steps
* Describe the behavior you observed after following the steps
* Explain which behavior you expected to see instead and why
* Include any error messages or logs

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, please include:

* Use a clear and descriptive title
* Provide a step-by-step description of the suggested enhancement
* Provide specific examples to demonstrate the steps
* Describe the current behavior and explain which behavior you expected to see instead
* Explain why this enhancement would be useful

### Pull Requests

* Fill in the required template
* Do not include issue numbers in the PR title
* Follow the Python style guides
* Include thoughtfully-worded, well-structured tests
* Document new code
* End all files with a newline

# Development Process

#### 1. Fork and download the repository

#### 2. Jump into the project directory
```console
$ cd anyrun-sdk
```

#### 3. Create a new virtual environment
```console
$ python3 -m venv venv
$ source venv/bin/activate
```

#### 4. Install project dev dependencies
```console
$ pip install -e .[dev]
```

#### 5. Create a new local branch
```console
$ git checkout -b <branch_title>
```

#### 6. Make your changes

#### 7. Run tests
```console
$ pytest --cov=anyrun --cov-report=term-missing -x
```

#### 8. Commit your changes
```console
$ git add .
$ git commit -m <commit_title>
```

#### 9. Push to the branch
```console
$ git push origin <branch_title>
```

### 10. Open a new pull request


# Style Guides

### Git Commit Title template

```console
$ git commit -m <commit_title>

Commit title template: [ImpactType]([ImpactScope]): [CommitChanges]
Example: feat(base_connector): add event-stream resolving, add new documentation
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

### Git Branch Title template
```console
$ git checkout -b <branch_title>

Branch title template: feature/public-[TaskShortDescription]
Example: feature/public-integration-tests-improvements
```
* **TaskShortDescription** - Feature name. Includes only lower case words separated by dashes

### Documentation Style Guide

* Use [reStructuredText](https://docutils.sourceforge.io/docs/user/rst/quickref.html) format for docstrings
* Document all public APIs
* Keep docstrings clear and concise
* Include examples in docstrings when appropriate
