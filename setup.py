#!/usr/bin/env python3

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="cloudguard-enhanced",
    version="2.0.0",
    author="Security Team",
    author_email="security@company.com",
    description="Production-ready AWS security scanner",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/company/cloudguard-enhanced",
    py_modules=["cg"],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
    ],
    python_requires=">=3.7",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "cloudguard=cg:main",
        ],
    },
    keywords="aws security scanner cloud compliance",
    project_urls={
        "Bug Reports": "https://github.com/company/cloudguard-enhanced/issues",
        "Source": "https://github.com/company/cloudguard-enhanced",
    },
)
