import os
import unittest

# test targets (addt'l imports above each packet/subpacket class)
from openpgp.sap.list import list_pkts

# package help
from openpgp.code import *
from openpgp.sap.armory import list_armored

# test help
from support import read_test_file


from openpgp.sap.pkt.CompressedData import CompressedData, create_CompressedDataBody
class CompressedDataTest(unittest.TestCase):
    """Test CompressedData Class"""

    #show_hex = lambda w,s: ''.join(['\\x' + hex(ord(c))[2:].zfill(2) for c in s])
    # TODO this is like 3 tests in one as a result of my lack of confidence
    # generating compressed data to test - so this goes through a Msg to
    # check the validity/plausibility of the decompressed packets, which of
    # course depends on the OnePassSignature, etc..
    def testDecomp2Packets(self):
        """CompressedData: packet instantiation, find packets in compressed data"""
        # compressed signature packet for key "A"
        # known good values (from gpg --list-packets):
        # algorithm = 1
        # contains data for 3 other packets:
        # 1 One-Pass Signature (type 4)
        # 2 Literal Data (type 11)
        # 3 Signature (type 2)
        comp_d = read_test_file(['pgpfiles','pkt','comp','comp.zip.sig.DSAELG1.pkt'])
        pkt = CompressedData(comp_d)
        cmpr = pkt.body
        self.assertEqual(cmpr.alg, 1)
        pkts = list_pkts(cmpr.data) # message should have 3 packets
        self.assertEqual(4, pkts[0].tag.type)
        self.assertEqual(11, pkts[1].tag.type)
        self.assertEqual(2, pkts[2].tag.type)
        # for extra credit..
        self.assertEqual(pkts[1].body.filename, "cleartext.txt")
        # (not testing literal data itself since I'm still not clear on 
        # \n and CR-LF issues

    def testB01CreateCompressed(self):
        """CompressedData: create_CompressedDataBody() no compression"""
        alg = COMP_UNCOMPRESSED
        d = "testing 1, 2, 3"
        compbody = create_CompressedDataBody(alg, d)
        self.assertEqual(d, compbody.data)

    def testB02CreateCompressed(self):
        """CompressedData: create_CompressedDataBody() ZIP compression"""
        alg = COMP_ZIP
        d = "testing 1, 2, 3"
        compbody = create_CompressedDataBody(alg, d)
        self.assertEqual(d, compbody.data)

    def testB03CreateCompressed(self):
        """CompressedData: create_CompressedDataBody() ZLIB compression"""
        alg = COMP_ZLIB
        d = "testing 1, 2, 3"
        compbody = create_CompressedDataBody(alg, d)
        self.assertEqual(d, compbody.data)


from openpgp.sap.pkt.LiteralData import LiteralData, create_LiteralDataBody
class LiteralDataTest(unittest.TestCase):
    """ """
    def testB01LiteralDataCreation(self):
        """LiteralData: create_LiteralDataBody() with known good"""
        _d = read_test_file(['pgpfiles','sig','sig.DSAELG1.onepass.gpg'])
        litpkt = list_pkts(_d)[1]
        litparams = {'data':litpkt.body.data,
                     'modified':litpkt.body.modified,
                     'format':litpkt.body.format,
                     'filename':litpkt.body.filename}
        litpktbody = create_LiteralDataBody(litparams)
        self.assertEqual(litpktbody._d, litpkt.body._d)


from openpgp.sap.pkt.MPI import create_MPI
class MPITest(unittest.TestCase):
    """
    """
    # Use known good mpi.value to create an instance..
    def testA01create_MPI(self):
        """MPI: create_MPI() using known good values"""
        key_d = read_test_file(['pgpfiles','key','DSAELG1.pub.gpg'])
        key = list_pkts(key_d)[0]
        mpis = [key.body.DSA_g, key.body.DSA_p, key.body.DSA_q, key.body.DSA_y]
        for mpi in mpis:
            new_mpi = create_MPI(mpi.value)
            self.assertEqual(new_mpi.value, mpi.value)
            self.assertEqual(new_mpi._d, mpi._d)
            self.assertEqual(new_mpi.length, mpi.length)
            self.assertEqual(new_mpi.bit_length, mpi.bit_length)
            self.assertEqual(new_mpi.size, mpi.size)


from openpgp.sap.pkt.OnePassSignature import create_OnePassSignatureBody
class OnePassSigntureTest(unittest.TestCase):
    """
    """
    def testB01OnePassSigntureCreation(self):
        """OnePassSignature: create_OnePassSignatureBody() with known good"""
        _d = read_test_file(['pgpfiles','sig','sig.DSAELG1.onepass.gpg'])
        onepass = list_pkts(_d)[0]
        opp = {'sigtype':onepass.body.type,
               'alg_hash':onepass.body.alg_hash,
               'alg_pubkey':onepass.body.alg_pubkey,
               'keyid':onepass.body.keyid,
               'nest':onepass.body.nest,
               'version':onepass.body.version}
        onepassbody = create_OnePassSignatureBody(opp)
        self.assertEqual(onepassbody._d, onepass.body._d)


from openpgp.sap.pkt.PublicKey import PublicKey
class PublicKeyTest(unittest.TestCase):
    # public key "A"
    # known good values (from gpg --list-packets):
    # version: 4
    # algorithm: 17
    # created: 1057429755
    # expires: 0 # this is being reported from the signature, since v4 public keys don't record expiration..
    # pkey[0] (DSA_p): [1024 bits]
    # pkey[1] (DSA_q): [160 bits]
    # pkey[2] (DSA_g): [1021 bits]
    # pkey[3] (DSA_y): [1023 bits]
    # fingerprint: 4D04 CE1D 89B4 995C 26F8  5E62 0CFC 2B6D CC07 9DF3

    def testPKValues(self):
        """PublicKey: check packet instance attributes"""
        key_d = read_test_file(['pgpfiles','pkt','pubkey','pubkey.DSAELG1.pkt'])
        pkt = PublicKey(key_d)
        pk = pkt.body
        self.assertEqual(pk.version, 4)
        self.assertEqual(pk.alg, 17)
        self.assertEqual(pk.created, 1057429755)
        self.assertEqual(pk.DSA_p.bit_length, 1024)
        self.assertEqual(pk.DSA_q.bit_length, 160)
        self.assertEqual(pk.DSA_g.bit_length, 1021)
        self.assertEqual(pk.DSA_y.bit_length, 1023)
        self.assertEqual(pk.fingerprint, '4D04CE1D89B4995C26F85E620CFC2B6DCC079DF3')

    # quick and dirty check that MPI value fiddling doesn't mess up MPI data
    # this just makes it obvious if code which calculates the fingerprint (MPI
    # data hash) doesn't match known good values
    def testKeyId(self):
        """PGP Key: check fingerprint"""
        pubkeyid = 'CC079DF3'
        subkeyid = 'A1F2BEF6'
        keyA = read_test_file(['pgpfiles','key','DSAELG1.pub.asc'])
        msg = list_pkts(list_armored(keyA)[0].data)
        self.assertEqual(pubkeyid, msg[0].body.fingerprint[-8:].upper())
        self.assertEqual(subkeyid, msg[3].body.fingerprint[-8:].upper())


from openpgp.sap.pkt.SecretKey import SecretKey
class SecretKeyTests(unittest.TestCase):
    """Secret Key Tests

    These tests check that the SecretKey class parses OpenPGP secret key
    information properly. They use list_pkts() and some lucky guessing
    instead of surgically removed packets to get the test packet
    information. This is unlike other tests that were written before
    list_pkts().

    ..Waitiing to finish test_cipher.py since decrypting secret key depends
    on it.
    """
    #### TODO
    #dsasec_d    = read_test_file(['pgpfiles','key','DSAELG1.sec.gpg'])
    #rsasec_d    = read_test_file(['pgpfiles','key','RSA1.sec.gpg'])
    ####
    def testA01DSANoPass(self):
        """SecretKey: check packet instance attributes, DSA no-password"""
        dsanopass_d = read_test_file(['pgpfiles','key','DSAELG1.sec.nopass.gpg'])
        key = list_pkts(dsanopass_d)[0].body
        self.assertEqual(key.version, 4)
        self.assertEqual(key.alg, 17)
        self.assertEqual(key.created, 1057429755)
        self.assertEqual(key.DSA_p.bit_length, 1024)
        self.assertEqual(key.DSA_q.bit_length, 160)
        self.assertEqual(key.DSA_g.bit_length, 1021)
        self.assertEqual(key.DSA_y.bit_length, 1023)
        self.assertEqual(key.DSA_x.bit_length, 157)
        self.assertEqual(key.id, '0CFC2B6DCC079DF3')
        self.assertEqual(key.fingerprint, '4D04CE1D89B4995C26F85E620CFC2B6DCC079DF3')

    def testA02RSANoPass(self):
        """SecretKey: check packet instance attributes, RSA no-password"""
        rsanopass_d = read_test_file(['pgpfiles','key','RSA1.sec.nopass.gpg'])
        key = list_pkts(rsanopass_d)[0].body
        self.assertEqual(key.version, 4)
        self.assertEqual(key.alg, 1)
        self.assertEqual(key.created, 1060345267)
        self.assertEqual(key.RSA_n.bit_length, 1024)
        self.assertEqual(key.RSA_e.bit_length, 6)
        self.assertEqual(key.RSA_d.bit_length, 1023)
        self.assertEqual(key.RSA_p.bit_length, 512)
        self.assertEqual(key.RSA_q.bit_length, 512)
        self.assertEqual(key.RSA_u.bit_length, 509)


from openpgp.sap.pkt.Signature import Signature, create_SignatureBody
class SignatureTest(unittest.TestCase):
    # get good known values from gpg --list-packets
    # I have no idea why these two share the same name but are different versions.
    detached_sig_d = read_test_file(['pgpfiles','sig','sig.DSAELG1.detached.gpg'])
    pubkey_sig_pkt = read_test_file(['pgpfiles','pkt','sig','sig.DSAELG1.pkt'])

    def testSig1(self):
        """Signature: v3 signature instance attributes"""
        pkt = Signature(self.detached_sig_d)
        sig = pkt.body
        self.assertEqual(sig.version, 3)
        self.assertEqual(sig.type, 0x00)
        self.assertEqual(sig.alg_pubkey, 17)
        self.assertEqual(sig.alg_hash, 2)
        self.assertEqual(sig.created, 1057881232)
        self.assertEqual(sig.keyid, '0CFC2B6DCC079DF3')

    def testSig2(self):
        """Signature: v4 signature instance attributes + subpackets"""
        pkt = Signature(self.pubkey_sig_pkt)
        sig = pkt.body
        self.assertEqual(sig.version, 4)
        self.assertEqual(sig.type, 0x13)
        self.assertEqual(sig.alg_pubkey, 17)
        self.assertEqual(sig.alg_hash, 2)
        self.assertEqual(sig.keyid, '0CFC2B6DCC079DF3')
        # check subpacket order, type, value, critical
        # ..even though no criticals should be set
        shs = sig.hashed_subpkts
        self.assertEqual((shs[0].type, shs[0].value, shs[0].critical), (2, 1057429755, 0))
        self.assertEqual((shs[1].type, shs[1].value, shs[1].critical), (11, [9, 8, 7, 3, 2], 0))
        self.assertEqual((shs[2].type, shs[2].value, shs[2].critical), (21, [2, 3], 0))
        self.assertEqual((shs[3].type, shs[3].value, shs[3].critical), (22, [2, 1], 0))
        self.assertEqual((shs[4].type, shs[4].value, shs[4].critical), (30, [1], 0))
        self.assertEqual((shs[5].type, shs[5].value, shs[5].critical), (23, [128], 0))
        sus = sig.unhashed_subpkts
        self.assertEqual((sus[0].type, sus[0].value), (16, '0CFC2B6DCC079DF3'))

    def testCreateSig(self):
        """Signature: create Signature DSA (using known good values)"""
        sigbody = Signature(self.pubkey_sig_pkt).body
        sigopts = {
        'version':sigbody.version, 
        'sigtype':sigbody.type, 
        'alg_pubkey':sigbody.alg_pubkey, 
        'alg_hash':sigbody.alg_hash, 
        'signature':(sigbody.DSA_r, sigbody.DSA_s), 
        'hash_frag':sigbody.hash_frag, 
        'hashed_subpkts':sigbody.hashed_subpkts, 
        'unhashed_subpkts':sigbody.unhashed_subpkts}
        newsigbody = create_SignatureBody(sigopts)
        self.assertEqual(sigbody._d, newsigbody._d)


from openpgp.sap.pkt.Signature import Signature, create_SignatureSubpacket
class SignatureSubpacketSanity(unittest.TestCase):
    """
    """
    def testA01KnownGood(self):
        """SignatureSubpacket: create_SignatureSubpacket() using known values"""
        pkt_d = read_test_file(['pgpfiles','pkt','sig','sig.DSAELG1.pkt'])
        sig = Signature(pkt_d)
        for good in sig.body.hashed_subpkts:
            subpkt = create_SignatureSubpacket(good.type, good.value)
            self.assertEqual(subpkt.type, good.type)
            self.assertEqual(subpkt.value, good.value)
        for good in sig.body.unhashed_subpkts:
            subpkt = create_SignatureSubpacket(good.type, good.value)
            self.assertEqual(subpkt.type, good.type)
            self.assertEqual(subpkt.value, good.value)
    # Covers the basic (shared) values per type.
    def testA02Sanity(self):
        """SignatureSubpacket: create_SignatureSubpacket() good names, values sanity"""
        import time
        t = int(time.time())
        subvals = [(SIGSUB_SIGNERID, '3366A0B0C0D0E0F0'),
                   (SIGSUB_CREATED, t),
                   (SIGSUB_REVOCABLE, 0),
                   (SIGSUB_TRUST, (56, 84)),
                   (SIGSUB_SYMCODE, [0, 1, 2]),
                   (SIGSUB_REVOKER, (1, 1, 'A1A2A3A4A5A6A7A8A9A0B1B2B3B4B5B6B7B8B9B0')),
                   (SIGSUB_NOTE, ([1,2,3,4], 'note name', 'note value')),
                   (SIGSUB_KEYSERV, 'SomeURL'),
                   (SIGSUB_REVOCREASON, (1, 'Oh, just because.'))]
        for vals in subvals:
            subpkt = create_SignatureSubpacket(vals[0], vals[1])
            self.assertEqual(subpkt.type, vals[0])
            self.assertEqual(subpkt.value, vals[1])


from openpgp.sap.pkt.UserID import UserID
class UserIDTest(unittest.TestCase):
    """Test UserID class against GnuPG-verified user id data."""

    def testUIDPacket(self):
        """UserID: instantiation through packet.Packet"""
        d = read_test_file(['pgpfiles','pkt','uid','userid.DSAELG1.pkt'])
        id = "Tester (Test Comment) <test@test.test>"
        pkt = UserID(d)
        self.assertEqual(id, pkt.body.value)


if '__main__' == __name__:
    unittest.main()



