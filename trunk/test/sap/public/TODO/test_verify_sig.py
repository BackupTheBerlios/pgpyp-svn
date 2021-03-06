"""Miscellaneous Signature Tests

This module should probably be dropped. I don't like the pkt2cryptokey
baloney and test_signature.py handles the evolution of signature
verification more elegantly.
"""

import os
import sha
import unittest
import pickle
import Crypto.PublicKey.DSA as DSA
from OpenPGP.packet import Packet
from OpenPGP.message import list_pkts
import OpenPGP.crypto as CRY
import OpenPGP.util.strnum as STN

# GnuPG source-scrounging:
# 
# Where I'm at is trying to find out what pk->pkey[1] 
# (actually, mpi_get_nbits(pk->pkey[0]) in sig-check.c:do_check())
# is in g10/seskey.c:do_encode_md() (where it is represented as nbits)
# this is to
# figure out how to calculate 'i' which determines the amount of
# '\xff' padding in RSA funkadoodle signatures. So far, the
# backwards grep has brought me to a likely candidate in getkey.c,
# which calls check_key_signature2() which sets the variable 'root'
# which is used to set the pk (pk = root->pkt->pkt.public_key).
# 
# At this point, I'm assuming that the deal just points to the
# number of bits in the public key MPI ..which in the gpg --verify
# output was 1024. So check whether the RSA modulus (n) or exponent (e)
# fits the bill.
#

class SignatureVerificationTest(unittest.TestCase):
    
    def setUp(self): 
        self.keydata = file('pgpfiles'+os.sep+'key'+os.sep+'DSAELG1.sec.nopass.gpg').read()
        self.keypkts = list_pkts(self.keydata)

    def testA02PyCryptoDSAVerification(self):
        """PyCrypto.PublicKey.DSA._verify: PyCrypto signature verification"""
        # this file has known good signature parameters
        sig = pickle.load(file('pgpfiles'+os.sep+'sig'+os.sep+'DSA_sig_test.pkl.py'))
        dsa = DSA.construct((sig['dsa_y'], sig['dsa_g'], sig['dsa_p'], sig['dsa_q'], sig['dsa_x']))
        r_s = dsa.sign(sig['msg'], sig['k'])
        ret = dsa.verify(sig['msg'], r_s)
        self.assertEqual(1, ret)

    def testA04Extract2PyCryptoDSA(self):
        """crypto.pkt2cryptokey: trivial DSA sign/verify with GnuPG values"""
        # the DSA values of a key (secret values accessible) generated by
        # GnuPG are being used to sign and verify a silly message, the
        # check being only that the public and private key values do in
        # fact work togther
        cryptokey = CRY.pkt2cryptokey(self.keypkts[0].body)
        sillymsg = 'test'
        sillykval = 100
        r_s = cryptokey.sign(sillymsg, sillykval)
        ret = cryptokey.verify(sillymsg, r_s)
        self.assertEqual(1, ret)

    def testCrtypokeyAttrs(self):
        """crypto.pkt2cryptokey: check DSA integer attribute equality"""
        key = self.keypkts[0].body
        cryptokey = CRY.pkt2cryptokey(key)
        self.assertEqual(key.DSA_p.value, cryptokey.p)
        self.assertEqual(key.DSA_q.value, cryptokey.q)
        self.assertEqual(key.DSA_y.value, cryptokey.y)
        self.assertEqual(key.DSA_g.value, cryptokey.g)

    def testD2VerifyGnuPGV3DSASig(self):
        """crypto.pkt2cryptokey: verify GnuPG V3 DSA one-pass signature"""
        sigdata = file('pgpfiles'+os.sep+'sig'+os.sep+'sig.DSAELG1.onepass.gpg').read()
        pktlist = list_pkts(sigdata)
        lit, sig = pktlist[1].body, pktlist[2].body
        key = self.keypkts[0].body
        cryptokey = CRY.pkt2cryptokey(key)
        # here, I *know* that this was signed using SHA1..
        msg = sha.new(lit.data + sig.hashed_data).digest()
        ret = cryptokey.verify(msg, (sig.DSA_r.value, sig.DSA_s.value))
        self.assertEqual(1, ret)

    def testD4VerifyGnuPGV3RSASig(self):
        """crypto.pkt2cryptokey: verify GnuPG V3 RSA one-pass signature"""
        
        rsasig_d = file('pgpfiles'+os.sep+'sig'+os.sep+'sig.RSA1.onepass.gpg').read()
        rsakey_d = file('pgpfiles'+os.sep+'key'+os.sep+'RSA1.pub.gpg').read()

        rsakeypkts, rsasigpkts = list_pkts(rsakey_d), list_pkts(rsasig_d)

        onepass, literal, sig = rsasigpkts[0].body, rsasigpkts[1].body, rsasigpkts[2].body
        
        key = rsakeypkts[0].body
        cryptokey = CRY.pkt2cryptokey(key)

        # grab the signature packet, see what the hashed value should be
        # see how it matches up with the hash fragments
        # the idea is to construct the hash value by hand and try to
        # match it up with "some" characters in gpg's do_encode_md().
        # again, I *know* that this was signed using SHA1..
        # "full hash prefix"?
        # SHA-1:      0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0E,
        #             0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14
        # 01 PS 00 T
        # PS is at least 8 octets of '\xff'

        msg = sha.new(literal.data + sig.hashed_data).digest()
        prefix = '\x30\x21\x30\x09\x06\x05\x2b\x0E\x03\x02\x1A\x05\x00\x04\x14'
        PS = ''
        for i in range (90):
            PS += '\xff'
        construct = '\x00\x01' + PS + '\x00' + prefix + msg
        # remember to tuple-ize the signature value
        ret = cryptokey.verify(construct, (sig.RSA.value,))
        self.assertEqual(1, ret)

if '__main__' == __name__:
    unittest.main()
