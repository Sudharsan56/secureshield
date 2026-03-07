"""
Legacy setup.py for compatibility with older pip versions.
The primary configuration is in pyproject.toml.
"""

from setuptools import setup, find_packages

with open("README.md", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="secureshield",
    version="1.0.0",
    description="Lightweight real-time web attack detection library for Python web applications",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="SecureShield Contributors",
    license="MIT",
    packages=find_packages(exclude=["tests*"]),
    python_requires=">=3.8",
    install_requires=[],
    extras_require={
        "dev": ["pytest>=7.0", "flask>=2.0"],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
    ],
    keywords="security web sql-injection xss firewall waf attack-detection",
    project_urls={
        "Homepage": "https://github.com/yourname/secureshield",
        "Bug Tracker": "https://github.com/yourname/secureshield/issues",
    },
)
