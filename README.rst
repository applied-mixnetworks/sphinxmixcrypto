
sphinx mix network crypto for python
====================================

.. image:: https://travis-ci.org/david415/sphinxmixcrypto.png?branch=master
    :target: https://www.travis-ci.org/david415/sphinxmixcrypto/
    :alt: travis

.. image:: https://coveralls.io/repos/github/david415/sphinxmixcrypto/badge.svg
    :target: https://coveralls.io/github/david415/sphinxmixcrypto
    :alt: coveralls



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

- https://github.com/david415/go-sphinxmixcrypto

Both projects contain the same unit test vectors, this proves binary compatiblity.


install
-------

You should install into a python virtual env.

Install pylioness from here:

- https://github.com/david415/pylioness


You can install it like this::

  pip install git+https://github.com/david415/pylioness.git

and then install this package::

  pip install git+https://github.com/david415/sphinxmixcrypto.git
