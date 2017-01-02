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


class ISphinxNodeState(zope.interface.Interface):
    """
    Interface for a class providing Sphinx mix node state.
    """
    replay_cache = zope.interface.Attribute("""replay_cache IPacketReplayCache""")
    zope.interface.invariant(IPacketReplayCache.providedBy(replay_cache))
    public_key = zope.interface.Attribute("""public_key 32 byte public key""")
    private_key = zope.interface.Attribute("""private_key 32 byte private key""")


class RandReader:
    def __init__(self):
        pass

    def read(self, n):
        return os.urandom(n)
