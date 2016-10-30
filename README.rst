
sphinxmixcrypto
---------------

sphinxmixcrypto is a python library for writing mixnets.
The code was forked from Ian Goldberg's reference implementation
of Sphinx from 2011.

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

You should probably install into a python virtual env.

I've replace the LIONESS implementation with my own:
https://github.com/david415/pylioness

You can install it like this::

  pip install git+https://github.com/david415/pylioness.git

and then install this package::

  pip install git+https://github.com/david415/sphinxmixcrypto.git
