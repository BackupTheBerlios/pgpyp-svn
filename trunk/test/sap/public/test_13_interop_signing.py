"""Signature Interoperation Tests"""

import os
import unittest

# test target
from openpgp.sap.crypto import verify

# package help
from openpgp.sap.armory import list_armored
from openpgp.sap.list import list_pkts, list_msgs

# test help
from support import sepjoin, read_test_file


# pgp6.5.3 RSA
p653rsadir = sepjoin(['pgpfiles','interop','pgp6.5.3','RSA1'])
p653rsapub60_d = read_test_file([p653rsadir,'key.pgp6.5.3.RSA1.6.0ext.pub.asc'])
p653rsasec60_d = read_test_file([p653rsadir,'key.pgp6.5.3.RSA1.6.0ext.sec.asc'])
p653rsapub_d = read_test_file([p653rsadir,'key.pgp6.5.3.RSA1.pub.asc'])
p653rsasec_d = read_test_file([p653rsadir,'key.pgp6.5.3.RSA1.sec.asc'])
p653rsasecnopass_d = read_test_file([p653rsadir,'key.pgp6.5.3.RSA1.sec.nopass.asc'])


class InteropSigPGP653A01RSA(unittest.TestCase):
    """PGP 6.5.3 RSA Signature Interop

    These tests cover interoperability with files created using
    PGP 6.5.3 RSA keys.
    """
    def testInteropP653SigA01RSA(self):
        "(interop) crypto.signature: verify PGP 6.5.3 RSA user ID"
        self.assertEqual(1, verify_armored_userid(p653rsapub_d))

    def testInteropP653SigA02RSA60(self):
        "(interop) crypto.signature: verify PGP 6.5.3 (w/6.0ext) RSA user ID"
        self.assertEqual(1, verify_armored_userid(p653rsapub60_d))

    def xtestInteropP653SigA9RSA60(self):
        "(interop) crypto.signature: verify PGP 6.5.3 secret RSA user ID"
        self.assertEqual(1, verify_armored_userid(p653rsasec_d))


# pgp6.5.3 DSA
p653dsadir = sepjoin(['pgpfiles','interop','pgp6.5.3','DHDSS1'])
p653dsapub60_d = read_test_file([p653dsadir,'key.pgp6.5.3.DHDSS1.6.0ext.pub.asc'])
p653dsasec60_d = read_test_file([p653dsadir,'key.pgp6.5.3.DHDSS1.6.0ext.sec.asc'])
p653dsapub_d = read_test_file([p653dsadir,'key.pgp6.5.3.DHDSS1.pub.asc'])
p653dsasec_d = read_test_file([p653dsadir,'key.pgp6.5.3.DHDSS1.sec.asc'])
p653dsasecnopass_d = read_test_file([p653dsadir,'key.pgp6.5.3.DHDSS1.sec.nopass.asc'])


class InteropSigPGP653A02DSA(unittest.TestCase):
    """PGP 6.5.3 DSA Signature Interop

    These tests cover interoperability with files created using
    PGP 6.5.3 DSA keys.
    """
    def testInteropP653SigA01DSA(self):
        "(interop) crypto.signature: verify PGP 6.5.3 DSA user ID"
        self.assertEqual(1, verify_armored_userid(p653dsapub_d))

    def testInteropP653SigA02DSA60(self):
        "(interop) crypto.signature: verify PGP 6.5.3 (w/6.0ext) DSA user ID"
        self.assertEqual(1, verify_armored_userid(p653dsapub60_d))

    def testInteropP653SigA03DSA60Subkey(self):
        "(interop) crypto.signature: verify PGP 6.5.3 (w/6.0ext) DSA subkey"
        self.assertEqual(1, verify_armored_subkey(p653dsapub60_d))

    def xtestInteropP653SigA9DSA60(self):
        "(interop) crypto.signature: verify PGP 6.5.3 secret DSA user ID"
        self.assertEqual(1, verify_armored_userid(p653dsasec_d))


# pgp7.0.3 DSA
p703dsadir = sepjoin(['pgpfiles','interop','pgp7.0.3'])
p703dsapub60_d = read_test_file([p703dsadir,'key.pgp7.0.3.DHDSS1.6.0ext.pub.asc'])
p703dsasec60_d = read_test_file([p703dsadir,'key.pgp7.0.3.DHDSS1.6.0ext.sec.asc'])
p703dsapub_d = read_test_file([p703dsadir,'key.pgp7.0.3.DHDSS1.pub.asc'])
p703dsasec_d = read_test_file([p703dsadir,'key.pgp7.0.3.DHDSS1.sec.asc'])
p703dsasecnopass_d = read_test_file([p703dsadir,'key.pgp7.0.3.DHDSS1.sec.nopass.asc'])


class InteropSigPGP703A02DSA(unittest.TestCase):
    """PGP 7.0.3 DSA Signature Interop

    These tests cover interoperability with files created using
    PGP 7.0.3 DSA keys.
    """
    def testInteropP703SigA01DSA(self):
        "(interop) crypto.signature: verify PGP 7.0.3 DSA user ID"
        self.assertEqual(1, verify_armored_userid(p703dsapub_d))

    def testInteropP703SigA02DSA60(self):
        "(interop) crypto.signature: verify PGP 7.0.3 (w/6.0ext) DSA user ID"
        self.assertEqual(1, verify_armored_userid(p703dsapub60_d))

    def testInteropP703SigA03DSA60Subkey(self):
        "(interop) crypto.signature: verify PGP 7.0.3 (w/6.0ext) DSA subkey"
        self.assertEqual(1, verify_armored_subkey(p703dsapub60_d))

    def xtestInteropP703SigA9DSA60(self):
        "(interop) crypto.signature: verify PGP 6.5.3 secret DSA user ID"
        self.assertEqual(1, verify_armored_userid(p703dsasec_d))


# pgp8.0.2 DSA
p802dsadir = sepjoin(['pgpfiles','interop','pgp8.0.2'])
p802dsapub60_d = read_test_file([p802dsadir,'key.pgp8.0.2.DHDSS1.6.0ext.pub.asc'])
p802dsasec60_d = read_test_file([p802dsadir,'key.pgp8.0.2.DHDSS1.6.0ext.sec.asc'])
p802dsapub_d = read_test_file([p802dsadir,'key.pgp8.0.2.DHDSS1.pub.asc'])
p802dsasec_d = read_test_file([p802dsadir,'key.pgp8.0.2.DHDSS1.sec.asc'])
p802dsasecnopass_d = read_test_file([p802dsadir,'key.pgp8.0.2.DHDSS1.sec.nopass.asc'])


class InteropSigPGP802A02DSA(unittest.TestCase):
    """PGP 8.0.2 DSA Signature Interop

    These tests cover interoperability with files created using
    PGP 8.0.2 DSA keys.
    """
    def testInteropP802SigA01DSA(self):
        "(interop) crypto.signature: verify PGP 8.0.2 DSA user ID"
        self.assertEqual(1, verify_armored_userid(p802dsapub_d))

    def testInteropP802SigA02DSA60(self):
        "(interop) crypto.signature: verify PGP 8.0.2 (w/6.0ext) DSA user ID"
        self.assertEqual(1, verify_armored_userid(p802dsapub60_d))

    def testInteropP802SigA03DSA60Subkey(self):
        "(interop) crypto.signature: verify PGP 8.0.2 (w/6.0ext) DSA subkey"
        self.assertEqual(1, verify_armored_subkey(p802dsapub60_d))

    def xtestInteropP802SigA9DSA60(self):
        "(interop) crypto.signature: verify PGP 8.0.2 secret DSA user ID"
        self.assertEqual(1, verify_armored_userid(p802dsasec_d))


def verify_armored_userid(armoreddata):
    akey = list_armored(armoreddata)[0]
    return verify_userid(akey.data)

def verify_userid(keydata):
    keymsg = list_msgs(list_pkts(keydata))[0]
    userid = keymsg._b_userids[0].leader # first user id
    useridsig = keymsg._b_userids[0].local_bindings[0] # first applicable signature
    pubkey = keymsg._b_primary.leader
    return verify(useridsig, userid, pubkey)

def verify_armored_subkey(armoreddata):
    akey = list_armored(armoreddata)[0]
    return verify_subkey(akey.data)

def verify_subkey(keydata):
    keymsg = list_msgs(list_pkts(keydata))[0]
    subkey    = keymsg._b_subkeys[0].leader # first subkey
    subkeysig = keymsg._b_subkeys[0].local_bindings[0] # first applicable signature
    pubkey    = keymsg._b_primary.leader # public key
    return verify(subkeysig, subkey, pubkey)


if '__main__' == __name__:
    unittest.main()
