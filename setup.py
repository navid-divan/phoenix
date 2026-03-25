from setuptools import setup, find_packages

setup(
    name="phoenix-voting",
    version="1.0.0",
    description="Post-quantum verifiable private voting system",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "tenseal>=0.3.14",
        "numpy>=1.24.0",
    ],
    extras_require={
        "dev": ["pytest>=7.0.0"],
    },
)
