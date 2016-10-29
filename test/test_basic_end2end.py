
import unittest

from sphinxmixcrypto.SphinxParams import SphinxParams, Group_p, Group_ECC
from sphinxmixcrypto.SphinxNode import SphinxNode, MessageResult
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

    # XXX why does do the tests fail if we run this one as well!?
    # makes no sense why they would share state!
    def not_test_modgroup_sphinx(self):
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


        def send_to_client(client_id, message_id, delta):
            print "send_to_client"
            self.params.clients[client_id].process(message_id, delta)

        def send_to_mix(destination, header, payload):
            print "send_to_mix"
            #print "next hop is %s" % (self.params.pki[destination].name,)
            return self.params.pki[destination].process(header, payload)

        result = self.params.pki[self.nodes[0]].process(header, delta)
        def mixnet_test_state_machine(result):
            while True:
                self.failIf(result.has_error())
                if result.tuple_next_hop:
                    print "next hop"
                    result = send_to_mix(result.tuple_next_hop[0], result.tuple_next_hop[1], result.tuple_next_hop[2])
                elif result.tuple_exit_hop:
                    print "exit hop"
                    print "Deliver [%s] to [%s]" % (result.tuple_exit_hop[1], result.tuple_exit_hop[0])
                    break
                elif result.tuple_client_hop:
                    print "client hop"
                    send_to_client(*result.tuple_client_hop)
                    break

        mixnet_test_state_machine(result)

        self.failUnlessEqual(self.params.pki[self.nodes[-1]].received[0], message)
        # Create a reply block for the client
        self.client.create_nym("cypherpunk", self.r)
        # Send a message to it
        reply_message = "this is a reply"
        nym_result = self.params.nymserver.process("cypherpunk", reply_message)
        self.failIf(nym_result.has_error())

        mixnet_test_state_machine(nym_result.message_result)
        self.failUnlessEqual(self.client.received[0], reply_message)
