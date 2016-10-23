# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import print_function

from setuptools import setup


description = '''
    Sphinx mixnet
'''

setup(
    name='sphinxmixcrypto',
    version='0.0.1',
    description=description,
    long_description=open('README', 'r').read(),
    keywords=['python','mixnet', 'cryptography', 'anonymity'],
    install_requires=open('requirements.txt').readlines(),
    classifiers=[
        'Topic :: Security',
    ],
    #author=__author__,
    #author_email=__contact__,
    #url=__url__,
    #license=__license__,
    packages=["sphinxmixcrypto"],
)
