# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import print_function

from setuptools import setup


description = '''
    Sphinx mixnet crypto
'''

setup(
    name='sphinxmixcrypto',
    version='0.0.1',
    description=description,
    long_description=open('README.rst', 'r').read(),
    keywords=['python','mixnet', 'cryptography', 'anonymity'],
    install_requires=open('requirements.txt').readlines(),
    classifiers=[
        'Topic :: Security',
    ],
    packages=["sphinxmixcrypto"],
)
