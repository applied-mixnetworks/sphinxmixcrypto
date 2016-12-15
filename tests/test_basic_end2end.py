
import py.test
import binascii
import cbor

from sphinxmixcrypto.params import SphinxParams, GroupECC, Chacha_Lioness, Chacha20_stream_cipher, Blake2_hash, Blake2_hash_mac
from sphinxmixcrypto import SphinxNode
from sphinxmixcrypto.node import ReplayError, BlockSizeMismatchError, SphinxNodeState
from sphinxmixcrypto.client import SphinxClient, rand_subset, create_forward_message
from sphinxmixcrypto.common import RandReader


class FixedNoiseReader():

    def __init__(self, hexed_noise):
        self.noise = binascii.unhexlify(hexed_noise)
        self.count = 0
        self.fallback = RandReader()

    def read(self, n):
        if n > len(self.noise):
            print("%s > %s" % (n, len(self.noise)))
            return self.fallback.read(n)
        ret = self.noise[:n]
        self.noise = self.noise[n:]
        self.count += n
        return ret


class TestSphinxCorrectness():

    def newTestRoute(self, numHops):
        self.r = numHops
        self.params = SphinxParams(
            self.r, group_class=GroupECC,
            hash_func=Blake2_hash,
            hash_mac_func=Blake2_hash_mac,
            lioness_class=Chacha_Lioness,
            stream_cipher=Chacha20_stream_cipher,
        )
        self.node_map = {}
        self.consensus = {}
        rand_reader = RandReader()
        for i in range(numHops):
            node = SphinxNode(self.params, rand_reader=rand_reader)
            self.node_map[node.get_id()] = node
            self.consensus[node.get_id()] = node.public_key
        route = rand_subset(self.node_map.keys(), self.r)
        return route

    def test_sphinx_single_hop(self):
        route = self.newTestRoute(1)
        destination = b"dest"
        message = b"this is a test"
        rand_reader = RandReader()
        alpha, beta, gamma, delta = create_forward_message(self.params, route, self.consensus, destination, message, rand_reader)
        header = alpha, beta, gamma
        payload = delta
        print("after create forward message")
        result = self.node_map[route[0]].unwrap(header, payload)
        assert len(result.tuple_exit_hop) == 2
        assert len(result.tuple_next_hop) == 0
        assert len(result.tuple_client_hop) == 0
        received_dest, received_message = result.tuple_exit_hop
        assert received_dest == destination
        assert received_message == message

    def test_sphinx_replay(self):
        route = self.newTestRoute(5)
        destination = b"dest"
        message = b"this is a test"
        rand_reader = RandReader()
        alpha, beta, gamma, delta = create_forward_message(self.params, route, self.consensus, destination, message, rand_reader)
        header = alpha, beta, gamma
        payload = delta
        self.node_map[route[0]].unwrap(header, payload)
        py.test.raises(ReplayError, self.node_map[route[0]].unwrap, header, payload)

    def test_sphinx_assoc_data(self):
        route = self.newTestRoute(5)
        destination = b"dest"
        message = b"this is a test"
        rand_reader = RandReader()
        alpha, beta, gamma, delta = create_forward_message(self.params, route, self.consensus, destination, message, rand_reader)
        header = alpha, beta, gamma
        payload = delta
        assert payload is not None
        py.test.raises(BlockSizeMismatchError, self.node_map[route[0]].unwrap, header, b"somethingelse!!!!!!!!!!!!!!")


class TestSphinxEnd2End():

    def setUpMixVectors(self, rand_reader):
        hexedState = [
            {
                "id": binascii.unhexlify("ff2182654d0000000000000000000000"),
                "public_key": binascii.unhexlify("d7314c8d2ba771dbe2982fa6299844f1b92736881e78ae7644f4bccbf8817a69"),
                "private_key": binascii.unhexlify("306e5a009897d4e134727037f9b275294bd01fb33c0c7dbe5f1fdaed765d0c47"),
            },
            {
                "id": binascii.unhexlify("ff0f9a62780000000000000000000000"),
                "public_key": binascii.unhexlify("5ce56657b8af66bd47df2469b10065206a2fd777a0cd17b104160256810bc976"),
                "private_key": binascii.unhexlify("98967364dfe5d5f5d0180c727797d9111f3b1da573c25036ba16396579c25048"),
            },
            {
                "id": binascii.unhexlify("ffc74d10550000000000000000000000"),
                "public_key": binascii.unhexlify("47ade5905376604cde0b57e732936b4298281c8a67b6a62c6107482eb69e2941"),
                "private_key": binascii.unhexlify("18c539194baae419f50ff117cbf15456a0762845af3d0a77ba85024ba488ce58"),
            },
            {
                "id": binascii.unhexlify("ffbb0407380000000000000000000000"),
                "public_key": binascii.unhexlify("4704aff4bc2aaaa3fd187d52913a203aba4e19f6e7b491bda8c8e67daa8daa67"),
                "private_key": binascii.unhexlify("781e6fc7636d70dae8ebf2337538b22d7b64281a55505c1f12921e7b61f09c59"),
            },
            {
                "id": binascii.unhexlify("ff81855a360000000000000000000000"),
                "public_key": binascii.unhexlify("73514173ee741afacdd4733e84f629b5cb9e34d28d072d749a8171fc6d64a930"),
                "private_key": binascii.unhexlify("9863a8f1b5307938cd4bc9782411e9eea0a38b9144d096bd923085dfb8534277"),
            },

        ]
        self.r = 5
        self.params = SphinxParams(
            self.r, group_class=GroupECC,
            hash_func=Blake2_hash,
            hash_mac_func=Blake2_hash_mac,
            lioness_class=Chacha_Lioness,
            stream_cipher=Chacha20_stream_cipher,
        )

        self.node_map = {}
        self.consensus = {}
        self.route = []

        # Create some nodes
        for i in range(len(hexedState)):
            state = SphinxNodeState()
            state.id = hexedState[i]['id']
            state.public_key = hexedState[i]['public_key']
            state.private_key = hexedState[i]['private_key']
            node = SphinxNode(self.params, state=state)
            self.route.append(node.id)
            self.node_map[node.get_id()] = node
            self.consensus[node.get_id()] = node.public_key

        # Create a client
        self.alice_client = SphinxClient(self.params,
                                         id=binascii.unhexlify("436c69656e74206564343564326264"),
                                         rand_reader=rand_reader)

    def test_client_surb(self):
        rand_reader = FixedNoiseReader("b5451d2eb2faf3f84bc4778ace6516e73e9da6c597e6f96f7e63c7ca6c9456018be9fd84883e4469a736c66fcaeceacf080fb06bc45859796707548c356c462594d1418b5349daf8fffe21a67affec10c0a2e3639c5bd9e8a9ddde5caf2e1db802995f54beae23305f2241c6517d301808c0946d5895bfd0d4b53d8ab2760e4ec8d4b2309eec239eedbab2c6ae532da37f3b633e256c6b551ed76321cc1f301d74a0a8a0673ea7e489e984543ca05fe0ff373a6f3ed4eeeaafd18292e3b182c25216aeb8")

        self.setUpMixVectors(rand_reader)
        self.bob_client = SphinxClient(self.params, rand_reader=rand_reader)

        nym_id = b"Cypherpunk"
        nym_tuple = self.alice_client.create_nym(self.route, self.consensus)

        ktilde = nym_tuple[2]
        print("\n\nsurb ktilde %s" % binascii.hexlify(ktilde))

        self.params.nymserver.add_surb(nym_id, nym_tuple)

        print("Bob sends a message to [%s]" % nym_id)
        reply_to_bob_surb = self.alice_client.create_nym(self.route, self.consensus)
        inner_message = {
            'surb': reply_to_bob_surb,
        }
        message = cbor.dumps(inner_message)
        print("size of serialized surb is %s" % len(message))
#        nym_result = self.params.nymserver.process(nym_id, message)
#        received_client_message = self.mixnet_test_state_machine(nym_result.message_result)
#        inner_message = cbor.loads(received_client_message)
#        assert 'surb' in inner_message
#        surb = inner_message['surb']
#        assert surb is not None
#        # XXX todo: Bob's send message on his choosen route to -> mix proxy to SURB -> Alice

    def mixnet_test_state_machine(self, result):
        i = 0
        while True:
            if result.tuple_next_hop:
                result = self.send_to_mix(result.tuple_next_hop[0], result.tuple_next_hop[1], result.tuple_next_hop[2])
                if self.route[i] == binascii.unhexlify("ffc74d10550000000000000000000000"):
                    assert result.tuple_next_hop[1][0] == binascii.unhexlify("b9bc2a81df782c98a8e2b8560dc50647e2f3c013ed563b021df3e0b45378d66c")  # alpha
                    assert result.tuple_next_hop[1][1] == binascii.unhexlify("9f486475acc1bd3bc551700f58108ea4029a250b5e893eaaf8aeb0811d84094816b3904f69d45921448454de0eb18bfda49832492a127a5682231d3848a3cb06ca17c3427063f80d662997b30bc9307a676cd6972716d1d6ee59b657f368b0fdb0245872e5157dd3de788341518c328395b415b516bd47efb86302edf840eebd9de432e08d6b9fddd4d55f75112332e403d78e536193aa172c0dbffbc9631d8c877214abef61d54bd0a35114e5f0eace")  # beta
                    assert result.tuple_next_hop[1][2] == binascii.unhexlify("0b05b2c7b3cdb8e5532d409be5f32a16")  # gamma
                    assert result.tuple_next_hop[2] == binascii.unhexlify("e6908ca25832a1f2f00e90f2f51ab1e407abcef6e4d3847c161e95705e7fcf8b7d9694b09989649aaf889b3c768c8ad5e8374f4410821f3e3fc3e6b838b84d14788756519b5dbcd785103c1daef9624bb3b57d763cc29f3b4aefad111129561719333d63c6b969ac3bf1d970a1b78ecc55eb5d1a2aaaf2e78bb783d756a1c3d46dc2dccfb51125b3cae26d0ef57f4b05cc92f8d2c37acc4743b4941af4e58ecd73834c0472ca3ba199b699c2c68babbd7237ee236eb6aada05c4146717bd9355d0afac129cb9246f1baeef7d7f4ec8177b8d7a32f9750c6e7f2ae1111301375cb9ccf6a218fa3970442e638febe4a7eafd73f165d53ad914aedcc5bf17e4c569d8dbe3b6827066a2193c88457e6bba94f678a64373cb1c2954dd8a80fd1c0723657779cfe0ae2238c44ae53e9b91ae70ff50d6b778a1a2c11030c41f29dfc00528784183664d8469fe0a404691bcd7cbaa1e57c8308f8fbbd76f7c0b77765a6f5f647c06527bf7b29ad58fbd2a58710503ebb6861dd449ff6df534c7622a8356d4858758de0ecb05174ce39e1c08634254b4552068d8b46f0a62e62648f12c6a32b290e295258176190c696a1f9d6c7641d3d004b47dca7914623a4855ad5fb93a144a017cdc1ad32ed1cc3dc6411f609c6f705da565f02589e9e443d8bfafa198895d71a51e45f7940938730086ffc7c480224aca67697ecce3546c4a84753a708d041ed2e5164128ffd92cdbd81e03c9af99135cbb89a96933d56d0671faebbbae21ca5e2a0154e76bd5dac36e55b983b725a878130e63313b20d9710610f3ed678d0de4442cb91e93613deaf09367f5bd1928218f0ccbc52c6046eac69039913986e60a139d063eda60975b1979a056b7bfc7635caa2ce094b77c7b36fb03f3d61183875a5dc1d4b8837a92e60669f585ca780a863ecfc0383d4361b474e3892b2361d5a7110cf1ccaf330f171dc0119861ee7c73976530f99534cdd9df0e52139de647ebbb8253c3f519e9c2acc06a671577231c7a910d09d98d79cf6db4f98e8b8b91f6e94bb0e122b002d3ea87e68f4c02ea863e45e281501d6b52bb599543d0008d5948a7e9aba0543b06e8a663cbd4e6db35e9b5d516684b57dc9f9db6a552f2e6d786c5e9d1d3c889ebe4798832e725367ad8637bd5691cf10649875b96ff488b4a22926724d0801d4df39598e4272d98ab2d2d1c7c60fc82e80974210fbc1d7f242afa57590796836e4376a17062c71b5e9ee8f40ecbba954af9129322891406b38af530e61e84966999470fa75452ebda7a79917054e6b226d7f6c85995d1485733544b2a2ebf0a2bd67445a6c061382a065ab273342975a2ac1fbb3a0f7fffd10afc18fb1bc4c315b92215160b9cdf0c09daa50d00463a6dd1fca64139df2d633b41cb2f50be46eaf821cea6b12cd361d953326386ccc87ecdb5")  # delta

                i += 1
            elif result.tuple_exit_hop:
                print("Deliver [%s] to [%s]" % (result.tuple_exit_hop[1], binascii.hexlify(result.tuple_exit_hop[0])))
                break
            elif result.tuple_client_hop:
                result = self.send_to_client(*result.tuple_client_hop)
                print("message received by [%s]" % result.tuple_message[0])
                return result.tuple_message[1]

    def send_to_client(self, client_id, message_id, delta):
        print("send_to_client client_id %s message_id %s delta len %s" % (client_id, binascii.hexlify(message_id), len(delta)))
        return self.params.clients[client_id].decrypt(message_id, delta)

    def send_to_mix(self, destination, header, payload):
        return self.node_map[destination].unwrap(header, payload)

    def test_end_to_end(self):
        rand_reader = FixedNoiseReader("82c8ad63392a5f59347b043e1244e68d52eb853921e2656f188d33e59a1410b43c78e065c89b26bc7b498dd6c0f24925c67a7ac0d4a191937bc7698f650391")
        self.setUpMixVectors(rand_reader)
        message = b"the quick brown fox"
        alpha, beta, gamma, delta = create_forward_message(self.params, self.route, self.consensus,
                                                           self.route[-1], message, rand_reader)
        header = alpha, beta, gamma

        # Send it to the first node for processing
        result = self.node_map[self.route[0]].unwrap(header, delta)
        self.mixnet_test_state_machine(result)
        assert self.node_map[self.route[-1]].received[0] == message
