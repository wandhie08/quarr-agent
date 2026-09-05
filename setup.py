from setuptools import find_packages, setup

setup(
    name="quarr-agent",
    version="1.0.0",
    description="QUARR — Autonomous Cyber Operations Agent. One Agent. Red. Blue. Forensics.",
    author="quarr-project",
    url="https://github.com/quarr-project/quarr-agent",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "pydantic>=2.0",
        "httpx>=0.27.0",
    ],
    entry_points={
        "console_scripts": [
            "quarr=main:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
    ],
)
