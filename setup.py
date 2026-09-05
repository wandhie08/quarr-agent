from setuptools import find_packages, setup

setup(
    name="quarr-agent",
    version="1.0.0",
    description="QUARR — Autonomous Cyber Operations Agent. One Agent. Red. Blue. Forensics.",
    author="quarr-project",
    url="https://github.com/wandhie08/quarr-agent",
    packages=find_packages(),
    py_modules=["main"],
    python_requires=">=3.10",
    install_requires=[
        # Core runtime (CLI agent) — required for `python main.py`.
        "pydantic>=2.0",
        "pydantic-settings>=2.0",
        "httpx>=0.27.0",
        "structlog>=23.0.0",
        "tenacity>=8.0.0",
        "python-dotenv>=1.0.0",
    ],
    extras_require={
        # Optional FastAPI/WebSocket backend + JWT auth (quarr/api/*).
        "api": [
            "fastapi>=0.110.0",
            "uvicorn>=0.29.0",
            "pyjwt>=2.8.0",
            "jinja2>=3.1.0",
        ],
        # Optional HashiCorp Vault secret provider.
        "vault": ["hvac>=2.0.0"],
        # Test/lint tooling.
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21",
            "pytest-cov>=4.0.0",
            "pytest-timeout>=2.3.0",
            "ruff>=0.4.0",
            "black>=24.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "quarr=main:run",
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
