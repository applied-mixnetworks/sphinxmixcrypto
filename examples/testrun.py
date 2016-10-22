#!/usr/bin/env python

# Copyright 2011 Ian Goldberg
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


import sys
import os

from sphinxmixnet.SphinxParams import SphinxParams
from sphinxmixnet.SphinxNode import SphinxNode, Denc, Dspec, pad_body, unpad_body
from sphinxmixnet.SphinxNymserver import Nymserver
from sphinxmixnet.SphinxClient import SphinxClient, rand_subset, create_forward_message

def main():
    use_ecc = (len(sys.argv) > 1 and sys.argv[1] == "-ecc")
    r = 5
    params = SphinxParams(r, ecc=use_ecc)

    # Create some nodes
    for i in xrange(2*r):
	SphinxNode(params)

    # Create a client
    client = SphinxClient(params)

    # Pick a list of nodes to use
    use_nodes = rand_subset(params.pki.keys(), r)

    header, delta = create_forward_message(params, use_nodes, "dest", \
	"this is a test")

    # Send it to the first node for processing
    params.pki[use_nodes[0]].process(header, delta)

    # Create a reply block for the client
    client.create_nym("cypherpunk", r)

    # Send a message to it
    params.nymserver.send_to_nym("cypherpunk", "this is a reply")
    


if __name__ == '__main__':
    main()
