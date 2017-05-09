#!/usr/bin/env python
from __future__ import absolute_import, division, print_function
import logging
from os import walk
from setuptools import setup, Command

logging.basicConfig(level=logging.DEBUG)
logging.getLogger("nose").setLevel(logging.DEBUG)

setup(
    name="rolemaker",
    version="0.2",
    packages=['rolemaker'],
    install_requires=["boto3", "Flask", "python-saml", "six"],
    setup_requires=["nose>=1.0"],

    # PyPI information
    author="David Cuthbert",
    author_email="cuthbert@amazon.com",
    description="Allow users to create AWS IAM roles in a restricted fashion",
    license="BSD",
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    keywords = ['aws', 'iam', 'role'],
    url = "https://github.com/dacut/rolemaker",
    zip_safe=False,
)
