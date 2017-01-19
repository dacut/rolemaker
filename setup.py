#!/usr/bin/env python
from __future__ import absolute_import, division, print_function
import logging
from os import walk
from setuptools import setup, Command

logging.basicConfig(level=logging.DEBUG)
logging.getLogger("nose").setLevel(logging.DEBUG)

webfiles = []
search_packages = ["rolemaker"]

for pkg in search_packages:
    for path, subdirs, files in walk(pkg):
        path = path[len(pkg) + 1:]
        if path:
            path += "/"
            
        webfiles.extend([path + f for f in files
                         if not f.endswith("~") and not f.startswith(".#")])

setup(
    name="rolemaker",
    version="0.2",
    packages=['rolemaker'],
    package_data={'rolemaker': webfiles,},
    data_files=[("/usr/local/libexec/rolemaker", ["rolemaker.wsgi"])],
    entry_points={
        "console_scripts": [
            "rolemaker-create-key=rolemaker.createkey:run_createkey",
            "rolemaker-daemon=rolemaker.daemon:run_daemon",
            "rolemaker-server=rolemaker.server:run_server",
        ]
    },
    install_requires=["boto>=2.0", "daemonize>=2.4", "Flask>=0.10",
                      "mako>=1.0"],
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
