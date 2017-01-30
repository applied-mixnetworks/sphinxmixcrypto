#!/usr/bin/env python

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

"""
error classes for mix decryption of sphinx packets
"""

# mix node errors

class HeaderAlphaGroupMismatchError(Exception):
    pass


class ReplayError(Exception):
    pass


class IncorrectMACError(Exception):
    pass


class InvalidProcessDestinationError(Exception):
    pass


class InvalidMessageTypeError(Exception):
    pass


class NoSURBSAvailableError(Exception):
    pass


class KeyMismatchError(Exception):
    pass


class SphinxBodySizeMismatchError(Exception):
    pass


# nymserver errors

class SphinxNoSURBSAvailableError(Exception):
    pass


# client errors

class NymKeyNotFoundError(Exception):
    pass


class CorruptMessageError(Exception):
    pass
