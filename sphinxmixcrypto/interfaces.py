# Copyright 2016-2017 David Stainton
#
# This file is part of Sphinx.
#
# Sphinx is free software: you can redistribute it and/or modify
# it under the terms of version 3 of the GNU Lesser General Public
# License as published by the Free Software Foundation.
#
# Sphinx is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with Sphinx.  If not, see
# <http://www.gnu.org/licenses/>.
#

import os
import zope.interface


class IMixPKI(zope.interface.Interface):
    """
    I am a mix network PKI interface. I'm only concerned
    with public keys of mixnet nodes.
    """
    def set(self, node_id, pub_key, addr):
        """
        if node_id isn't already present then set an associated public key and connecting address
        """

    def get(self, node_id):
        """
        given a node_id, return the public key
        -> 32 byte key
        """

    def identities(self):
        """
        return a list of key ID's
        -> [node_id]
        """

    def get_mix_addr(self, transport_name, node_id):
        """
        given a node id and a transport name return the connecting information
        """

    def rotate(self, node_id, new_pub_key, signature):
        """
        rotate mixnet node keys; I remove the old PKI entry's public key
        and replace it with the new public key if the signature
        can be verified using the old public key.
        """


class IPacketReplayCache(zope.interface.Interface):
    """
    Interface to a Sphinx packet replay tag cache which
    is used to detect replayed Sphinx packets.
    """

    def has_seen(self, tag):
        """
        Returns True if the tag has been seen, otherwise False.
        """

    def set_seen(self, tag):
        """
        Sets the tag into the cache so that subsequent calls to
        has_seen will return True.
        """

    def flush(self):
        """
        Flushes cache, all entries are removed.
        """


class IKeyState(zope.interface.Interface):
    """
    key state interface providers getters from public and private keys
    """

    def get_public_key(self):
        """
        return the public key, a 32 byte value
        """

    def get_private_key(self):
        """
        return the private key, a 32 byte value
        """


class IReader(zope.interface.Interface):
    """
    i'm an interface used for bytes for generating key material.
    this assists our writing of deterministic unit tests.
    """

    def read(self, n):
        """
        return n bytes
        """
