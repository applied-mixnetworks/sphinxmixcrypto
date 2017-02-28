
sphinx mix network crypto for python
====================================

.. image:: http://img.shields.io/pypi/v/sphinxmixcrypto.svg
   :target: https://pypi.python.org/pypi/sphinxmixcrypto
   :alt: PyPI Package

.. image:: https://travis-ci.org/applied-mixnetworks/sphinxmixcrypto.png?branch=master
    :target: https://www.travis-ci.org/applied-mixnetworks/sphinxmixcrypto/
    :alt: travis

.. image:: https://coveralls.io/repos/github/applied-mixnetworks/sphinxmixcrypto/badge.svg
    :target: https://coveralls.io/github/applied-mixnetworks/sphinxmixcrypto
    :alt: coveralls


Warning
=======
This code has not been formally audited by a cryptographer. It therefore should not
be considered safe or correct. Use it at your own risk!


sphinxmixcrypto
---------------

Read the Sphinx paper:

**Sphinx: A Compact and Provably Secure Mix Format**
by Ian Goldberg and George Danezis

- http://www0.cs.ucl.ac.uk/staff/G.Danezis/papers/sphinx-eprint.pdf


This is a crypto library for writing mix networks.
The code was forked from Ian Goldberg's reference implementation.


status
------

This crypto library is binary compatible with the golang sphinx crypto library:

- https://github.com/applied-mixnetworks/go-sphinxmixcrypto

Both projects contain the same unit test vectors.


install
-------

Pypi packages available

  pip install sphinxmixcrypto

or install from github into a python virtual env

  pip install git+https://github.com/applied-mixnetworks/sphinxmixcrypto.git
