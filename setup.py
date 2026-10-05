from setuptools import setup, find_packages

setup(
    name="ulpf",
    version="2.0.0",
    description="Universal Log Pre-processing Framework (ULPF) - Production CLI & Engine",
    author="Team LunarX",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "ulpf=core.cli:main",
        ],
    },
    install_requires=[
        "duckdb>=1.0.0",
        "pyarrow>=14.0.0",
        "pandas>=2.0.0",
        "cryptography>=41.0.0",
        "zstandard>=0.22.0",
        "pyyaml>=6.0",
        "drain3>=0.9.11",
    ],
    python_requires=">=3.9",
)
