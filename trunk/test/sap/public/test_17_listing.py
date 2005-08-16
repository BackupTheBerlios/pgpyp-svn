"Packet and message listing tests"

import os
import unittest

# test targets
from openpgp.sap.list import list_as_signed
from openpgp.sap.list import find_key_prefs
from openpgp.sap.list import find_keys
from openpgp.sap.list import list_msgs
from openpgp.sap.list import list_pkts

# package help
from openpgp.sap.armory import list_armored
from openpgp.sap.exceptions import PGPError
from openpgp.sap.msg.KeyMsg import PublicKeyMsg
from openpgp.sap.msg.SignedMsg import SignedMsg
from openpgp.sap.pkt.Signature import Signature

# test help
from support import curdir, sepjoin, read_test_file

class B00PublicKeyTests(unittest.TestCase):
    """sap Public Key Tests

    The various public key tests are checked here..
    """
    # Check that the order of a single keymsg's prefs aren't disturbed.
    def testB02Preferences(self):
        """sap.api: find_key_prefs() single key"""
        key_d = read_test_file(['pgpfiles','key','DSAELG1.pub.gpg'])
        keymsg = list_msgs(list_pkts(key_d))[0]
        preferred = find_key_prefs([keymsg])
        self.assertEqual(preferred['sym'], [9, 8, 7, 3, 2])
        self.assertEqual(preferred['hash'], [2, 3])
        self.assertEqual(preferred['comp'], [2, 1])
    # Check that same values don't interfere.
    def testB03MultiplePreferencesSameValues(self):
        """sap.api: find_key_prefs() two keys, same values"""
        key1_d = read_test_file(['pgpfiles','key','DSAELG1.pub.gpg'])
        keymsg1 = list_msgs(list_pkts(key1_d))[0]
        key2_d = read_test_file(['pgpfiles','key','RSA1.pub.gpg'])
        keymsg2 = list_msgs(list_pkts(key2_d))[0]
        preferred = find_key_prefs([keymsg1, keymsg2])
        self.assertEqual(preferred['sym'], [9, 8, 7, 3, 2])
        self.assertEqual(preferred['hash'], [2, 3])
        self.assertEqual(preferred['comp'], [2, 1])
    # Something a little more real. 
    def testB04MultiplePreferencesDifferentValues(self):
        """sap.api: find_key_prefs() two keys, different values"""
        key1_d = read_test_file(['pgpfiles','key','DSAELG1.pub.gpg'])
        # sym[9, 8, 7, 3, 2], hash[2, 3], comp[2, 1]
        keymsg1 = list_msgs(list_pkts(key1_d))[0]
        key2_d = read_test_file(['pgpfiles','interop','pgp8.0.2','key.pgp8.0.2.DHDSS1.pub.asc'])
        d = list_armored(key2_d)[0].data
        # sym[9, 8, 7, 3, 2, 10], empty hash, empty comp
        keymsg2 = list_msgs(list_pkts(d))[0]
        preferred = find_key_prefs([keymsg1, keymsg2])
        self.assertEqual(preferred['sym'], [9, 8, 7, 3, 2])
        self.assertEqual(preferred['hash'], [])
        self.assertEqual(preferred['comp'], [])


class Test_list_as_signed(unittest.TestCase):

    def testA01NativeDSAPublicKey(self):
        "list: list_as_signed() DSA public key"
        d = read_test_file(['pgpfiles','key','DSAELG1.pub.gpg'])
        players = list_as_signed(d)
        self.assertEqual(PublicKeyMsg, players[0].__class__)
        self.assertEqual(1, len(players))

    def testA02ArmoredRSAPublicKey(self):
        "list: list_as_signed() RSA public key, ASCII-armored"
        d = read_test_file(['pgpfiles','key','RSA1.pub.gpg'])
        players = list_as_signed(d)
        self.assertEqual(PublicKeyMsg, players[0].__class__)
        self.assertEqual(1, len(players))

    def testA03DSAClearsigned(self):
        "list: list_as_signed() DSA clearsigned (ASCII-armored) signature"
        d = read_test_file(['pgpfiles','sig','sig.DSAELG1.clear.asc'])
        players = list_as_signed(d)
        # looking for players = [([sig], msg)]
        self.assertEqual(Signature, players[0][0][0].__class__)
        self.assertEqual(True, isinstance(players[0][1], str))
        self.assertEqual(1, len(players))

    def testA04DSANativeOnePass(self):
        "list: list_as_signed() DSA one-pass signature"
        d = read_test_file(['pgpfiles','sig','sig.DSAELG1.onepass.gpg'])
        players = list_as_signed(d)
        # looking for players = [signed_msg]
        self.assertEqual(SignedMsg, players[0].__class__)
        self.assertEqual(1, len(players))

    def testA05DSADetached(self):
        "list: list_as_signed() DSA detached signature"
        d = read_test_file(['pgpfiles','sig','sig.DSAELG1.detached.gpg'])
        det_d = read_test_file(['pgpfiles','cleartext.txt'])
        players = list_as_signed(d, detached=det_d)
        # looking for players = [([sig], msg)]
        self.assertEqual(Signature, players[0][0][0].__class__)
        self.assertEqual(True, isinstance(players[0][1], str))
        self.assertEqual(1, len(players))

    def testA06DSACompressed(self):
        "list: list_as_signed() DSA compressed one-pass signature"
        d = read_test_file(['pgpfiles','sig','sig.DSAELG1.comp.gpg'])
        players = list_as_signed(d, decompress=True)
        # looking for players = [signed_msg], since decompression is automatic
        self.assertEqual(SignedMsg, players[0].__class__)
        self.assertEqual(1, len(players))


if '__main__' == __name__:
    unittest.main()
