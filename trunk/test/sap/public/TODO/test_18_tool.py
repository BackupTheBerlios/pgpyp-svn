"""PGP tool tests"""

import unittest

# test targets
from openpgp.sap.util.tool import cat_pkt_str
from openpgp.sap.util.tool import slice_msg_str

# test help
from support import read_test_file

class A00PacketConcatenation(unittest.TestCase):
    """
    """
    def testJ01CatKeys(self):
        "cat_packets() multiple keys"
        key_d = read_test_file(['pgpfiles','key','DSAELG_1_and_3.pub.asc'])
        pkts = cat_pkt_str([key_d, key_d])
        msgs = list_msgs(pkts)[0]
        # since we just duplicated the two keys, 0,2 and 1,3 should be the same
        self.assertEqual(msgs[0].rawstr(), msgs[2].rawstr())
        self.assertEqual(msgs[1].rawstr(), msgs[3].rawstr())

class A02PacketSlices(unittest.TestCase):
    """
    """
    # so these guys are choking thanks to some oddball probs with list_players()
    # gotta just replace list_players altogether..
    # the question then is how to test this, since the test will look just
    # like the logic used to create it in the first place..
    def testI01SingleSlice(self):
        "slice_msg_str() single packet, first message: 0[1]" 
        key_d = read_test_file(['pgpfiles','key','DSAELG_1_and_3.pub.asc'])
        slice_d = "0[1]" # first message, second packet is a user ID
        pkts = slice_msg_str(key_d, slice_d)
        armored_pkts = sap_out(pkts, None, True) # check funky armoring
        l = []
        players = list_players(armored_pkts[0]['data'], None, leftovers=l)
        self.assertEqual(pkts[0].rawstr(), l[0].rawstr())
    
    def testI02MultipleSlice(self):
        "slice_msg_str() multiple packets, second message: 1[2:4]" 
        key_d = read_test_file(['pgpfiles','key','DSAELG_1_and_3.pub.asc'])
        slice_d = "1[2:4]" # second message, third and fourth packets
        pkts = slice_msg_str(key_d, slice_d)
        armored_pkts = sap_out(pkts, None, True) # check funky armoring
        l = []
        players = list_players(armored_pkts[0]['data'], None, leftover=l)
        self.assertEqual(pkts[0].rawstr(), l[0].rawstr())
        self.assertEqual(pkts[1].rawstr(), l[1].rawstr())

    def testI03LeftoverSlice(self):
        "slice_msg_str() single leftover packet: L[0]" 
        key_d = read_test_file(['pgpfiles','key','DSAELG1.primary_revoc_cert.asc'])
        slice_d = "L[0]" # first leftover packet (detached signature) 
        pkts = slice_msg_str(key_d, slice_d)
        print pkts
        armored_pkts = sap_out(pkts, None, True) # check funky armoring
        l = []
        players = list_players(armored_pkts[0]['data'], None, leftovers=l)
        print players, l
        self.assertEqual(pkts[0].rawstr(), l[0].rawstr())


if '__main__' == __name__:
    unittest.main()
