# anyrun-sdk/setup.py
import setuptools

if __name__ == "__main__":
    setuptools.setup(
        name="anyrun-sdk",
        version="1.9.6",
        author="Semen Shalnev, Danila Korolev",
        author_email="anyrun-integrations@any.run",
        description="This is the official Python client library for ANY.RUN. Automate management of ANY.RUN REST endpoints",
        long_description=open("README.md").read(),
        long_description_content_type="text/markdown",
        url="https://github.com/anyrun/anyrun-sdk",
        packages=setuptools.find_packages(),
        install_requires=[
            "aiohttp==3.6.3",
            "aiofiles==0.6.0",
            "typing-extensions==3.10.0.2",
            "requests==2.25.1"
        ],
        classifiers=[
            "Programming Language :: Python :: 3.5",
            "Programming Language :: Python :: 3.6",
            "Programming Language :: Python :: 3.7",
            "Programming Language :: Python :: 3.8",
            "Topic :: Software Development :: Libraries",
            "Typing :: Typed"
        ],
        python_requires=">=3.5"
    )