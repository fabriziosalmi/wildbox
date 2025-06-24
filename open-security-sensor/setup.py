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
with open('README.md', 'r', encoding='utf-8') as f:
    long_description = f.read()

# Read requirements
with open('requirements.txt', 'r', encoding='utf-8') as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]

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
    'linux': [
        'python-systemd>=234'
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
