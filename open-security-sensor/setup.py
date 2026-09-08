#!/usr/bin/env python3
"""
Setup script for Open Security Sensor
"""

from setuptools import setup, find_packages
import sys
import os

# Read version from package
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'sensor'))
try:
    from sensor import __version__
except ImportError:
    __version__ = '1.0.0'

# Read long description from README
# Optional: README.md is documentation and is excluded from the Docker build
# context, so opening it unconditionally made `pip install -e .` fail inside the
# image with FileNotFoundError -- the package metadata should not depend on a
# file that is not part of the package.
try:
    with open('README.md', 'r', encoding='utf-8') as f:
        long_description = f.read()
except FileNotFoundError:
    long_description = ''

# Read requirements from requirements.in, not requirements.txt.
#
# requirements.txt is now a uv-compiled lockfile: every entry carries
# `--hash=sha256:...` continuation lines, which are pip install options and not
# requirement specifiers. Feeding those to install_requires fails metadata
# generation outright ("must be a string or iterable of strings containing valid
# project/version requirement specifiers"). requirements.in holds the direct
# dependencies, which is what install_requires is supposed to describe; the
# lockfile stays the thing the image installs.
def _read_requirements():
    for candidate in ('requirements.in', 'requirements.txt'):
        try:
            with open(candidate, 'r', encoding='utf-8') as fh:
                lines = fh.read().splitlines()
        except FileNotFoundError:
            continue
        reqs = []
        for line in lines:
            line = line.split('#', 1)[0].strip().rstrip('\\').strip()
            # Skip blanks, pip options (-r, --hash, --index-url) and the hash
            # continuations that follow a pinned requirement.
            if not line or line.startswith('-'):
                continue
            reqs.append(line)
        if reqs:
            return reqs
    return []


requirements = _read_requirements()

# Platform-specific requirements
extra_requirements = {
    'dev': [
        'pytest>=7.2.0',
        'pytest-asyncio>=0.20.3',
        'pytest-cov>=4.0.0',
        'black>=22.10.0',
        'flake8>=6.0.0',
        'mypy>=0.991'
    ],
    'windows': [
        'pywin32>=304',
        'wmi>=1.5.1'
    ],
    'macos': [
        'pyobjc-framework-Cocoa>=9.0'
    ]
}

setup(
    name='open-security-sensor',
    version=__version__,
    description='A lightweight, high-performance, cross-platform endpoint agent for comprehensive security telemetry collection',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Open Security Team',
    author_email='security@wildbox.com',
    url='https://github.com/wildbox/open-security-sensor',
    packages=find_packages(),
    include_package_data=True,
    python_requires='>=3.8',
    install_requires=requirements,
    extras_require=extra_requirements,
    entry_points={
        'console_scripts': [
            'security-sensor=main:main',
            'ossensor=main:main',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Topic :: System :: Monitoring',
        'Topic :: Security',
        'Topic :: System :: Systems Administration',
    ],
    keywords='security monitoring endpoint detection response osquery telemetry',
    project_urls={
        'Bug Reports': 'https://github.com/wildbox/open-security-sensor/issues',
        'Source': 'https://github.com/wildbox/open-security-sensor',
        'Documentation': 'https://github.com/wildbox/open-security-sensor/blob/main/README.md',
    },
    data_files=[
        ('etc/security-sensor', ['config.yaml.example']),
    ],
    zip_safe=False,
)
