README
======

.. image:: https://travis-ci.org/david415/sphinxmixcrypto.png?branch=master
    :target: https://www.travis-ci.org/david415/sphinxmixcrypto/
    :alt: travis

.. image:: https://coveralls.io/repos/github/david415/sphinxmixcrypto/badge.svg
    :target: https://coveralls.io/github/david415/sphinxmixcrypto
    :alt: coveralls



sphinxmixcrypto
---------------

sphinxmixcrypto is a python crpyto library for writing mixnets.
The code was forked from Ian Goldberg's reference implementation
of Sphinx from 2011.

Read the Sphinx paper:

**Sphinx: A Compact and Provably Secure Mix Format**
http://www0.cs.ucl.ac.uk/staff/G.Danezis/papers/sphinx-eprint.pdf

This library intentionally does not have any networking code.
It is a crypto library. You can look at the unit tests to see
how a Sphinx Node state-machine is built.

This library allows you to make parameterized sphinx packets,
with the crypto primitives of your choosing. The unit tests
currently demonstrate use of more modern crypto primitives
than the original Sphinx reference implementation, such as:
Chacha20 for the stream cipher and a new Lioness implementation
using Chacha20 + Blake2.


install
-------

You should install into a python virtual env.

I've replaced the LIONESS implementation with my own:
https://github.com/david415/pylioness

You can install it like this::

  pip install git+https://github.com/david415/pylioness.git

and then install this package::

  pip install git+https://github.com/david415/sphinxmixcrypto.git
