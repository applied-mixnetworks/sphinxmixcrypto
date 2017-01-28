# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import print_function

from setuptools import setup

# Hmmmph.
# So we get all the meta-information in one place (yay!) but we call
# exec to get it (boo!). Note that we can't "from txtorcon._metadata
# import *" here because that won't work when setup is being run by
# pip (outside of Git checkout etc)
with open('sphinxmixcrypto/_metadata.py') as f:
    exec(
        compile(f.read(), '_metadata.py', 'exec'),
        globals(),
        locals(),
    )

description = '''
    Sphinx mixnet crypto
'''

setup(
    name='sphinxmixcrypto',
    version=__version__,
    description=description,
    long_description=open('README.rst', 'r').read(),
    keywords=['python', 'mixnet', 'cryptography', 'anonymity'],
    install_requires=open('requirements.txt').readlines(),
    # "pip install -e .[dev]" will install development requirements
    extras_require=dict(
        dev=open('dev-requirements.txt').readlines(),
    ),
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Topic :: Security :: Cryptography',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
    ],
    author=__author__,
    author_email=__contact__,
    url=__url__,
    license=__license__,
    packages=["sphinxmixcrypto"],
)
