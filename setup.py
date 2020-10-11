import pathlib
from setuptools import setup

# The directory containing this file
HERE = pathlib.Path(__file__).parent

# The text of the README file
README = (HERE / "README.md").read_text()

setup(
    name="nosplash",
    version="0.1.0",
    description="A simple script utility that allows you to extract and set custom splash inside EWSF.EWS",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/morsisko/NosSplash",
    author="morsisko",
    license="MIT",
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Development Status :: 5 - Production/Stable",
    ],
    packages=["nosplash"],
    scripts=["nosplash/nosplash.py"],
)
