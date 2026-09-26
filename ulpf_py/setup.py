from setuptools import setup, find_packages

setup(
    name="ulpf-py",
    version="1.0.0",
    description="Universal Log Pre-processing Framework Python SDK (NTRO SIH26156)",
    author="Team LunarX",
    packages=find_packages(),
    install_requires=[
        "duckdb>=1.0.0",
        "pyarrow>=14.0.0",
        "pandas>=2.0.0",
        "cryptography>=41.0.0",
        "zstandard>=0.22.0",
    ],
    python_requires=">=3.9",
)
