#!/usr/bin/env python3
"Setuptools params"

from setuptools import setup, find_packages

VERSION = '0.1'

modname = distname = 'advnet_utils'

def readme():
    with open('README.md','r') as f:
        return f.read()

setup(
    name=distname,
    version=VERSION,
    description='Adv-net project utilities',
    author='Edgar Costa Molero',
    author_email='cedgar@ethz.ch',
    packages=find_packages(),
    long_description=readme(),
    include_package_data = True,
    keywords='education networking p4 mininet',
    install_requires=[
        'ipaddr',
        'ipaddress',
        'networkx',
        'psutil',
        'setuptools',
    ],
    extras_require={}
)