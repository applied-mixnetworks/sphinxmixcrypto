
import unittest

from sphinxmixcrypto.SphinxParams import SphinxParams, Group_p, Group_ECC
from sphinxmixcrypto.SphinxNode import SphinxNode
from sphinxmixcrypto.SphinxClient import SphinxClient, rand_subset, create_forward_message



class TestModGroup(unittest.TestCase):

    def setUp(self):
        self.r = 5
        self.params = SphinxParams(self.r, group_class = Group_p)
        # Create some nodes
        for i in xrange(2*self.r):
            SphinxNode(self.params)
        # Create a client
        self.client = SphinxClient(self.params)
        # Pick a list of nodes to use
        self.nodes = rand_subset(self.params.pki.keys(), self.r)

    def test_modgroup_sphinx(self):
        message = "this is a test"
        header, delta = create_forward_message(self.params, self.nodes, "dest", message)
        # Send it to the first node for processing
        self.params.pki[self.nodes[0]].process(header, delta)
        self.failUnlessEqual(self.params.pki[self.nodes[-1]].received[0], message)
        # Create a reply block for the client
        self.client.create_nym("cypherpunk", self.r)
        # Send a message to it
        reply_message = "this is a reply"
        self.params.nymserver.send_to_nym("cypherpunk", reply_message)
        self.failUnlessEqual(self.client.received[0], reply_message)


class TestECCGroup(unittest.TestCase):

    def setUp(self):
        self.r = 5
        self.params = SphinxParams(self.r, group_class = Group_ECC)
        # Create some nodes
        for i in xrange(2*self.r):
            SphinxNode(self.params)
        # Create a client
        self.client = SphinxClient(self.params)
        # Pick a list of nodes to use
        self.nodes = rand_subset(self.params.pki.keys(), self.r)

    def test_eccgroup_sphinx(self):
        message = "this is a test"
        header, delta = create_forward_message(self.params, self.nodes, "dest", message)
        # Send it to the first node for processing
        self.params.pki[self.nodes[0]].process(header, delta)
        self.failUnlessEqual(self.params.pki[self.nodes[-1]].received[0], message)
        # Create a reply block for the client
        self.client.create_nym("cypherpunk", self.r)
        # Send a message to it
        reply_message = "this is a reply"
        self.params.nymserver.send_to_nym("cypherpunk", reply_message)
        self.failUnlessEqual(self.client.received[0], reply_message)
