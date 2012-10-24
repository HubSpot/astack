#!/usr/bin/env python
# -*- coding: utf-8 -
from setuptools import setup

setup(
    name='astack',
    version='0.0.1',
    description='Simple stacktrace analysis tool for the JVM',
    long_description=open('README.rst').read(),
    author='Michael Axiak',
    author_email='mike@axiak.net',
    license=open('LICENSE').read(),
    url='https://www.github.com/HubSpot/astack/',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Other Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
    ],
    include_package_data=True,
    entry_points={
        'console_scripts':
        ['astack=astack:main'],
    })
