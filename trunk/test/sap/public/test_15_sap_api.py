"""sap API Tests"""

import unittest
import os
import time

# test targets
#from openpgp.sap.api import sap_out
from openpgp.sap.api import verify_block
from openpgp.sap.api import verify_msg
from openpgp.sap.api import decrypt_msg
from openpgp.sap.api import encrypt_msg
from openpgp.sap.api import sign_msg

# package help
from openpgp.code import *
from openpgp.sap.exceptions import *
from openpgp.sap.armory import list_armored
from openpgp.sap.list import list_pkts, list_msgs
from openpgp.sap.msg.LiteralMsg import create_LiteralMsg
from openpgp.sap.crypto import encrypt_public_session
from openpgp.sap.crypto import encrypt_integrity
from openpgp.sap.crypto import gen_random
from openpgp.sap.crypto import _keysize # ugly
from openpgp.sap.pkt.Packet import create_Packet
from openpgp.sap.pkt.LiteralData import create_LiteralDataBody
from openpgp.sap.pkt.CompressedData import create_CompressedDataBody

# test help
from support import sepjoin, curdir, read_test_file


#class A01SapOutput(unittest.TestCase):
#    """String input/output compatibility.
#
#    sap_out() and list_players() are reciprocal functions in that
#    sap_out() creates OpenPGP strings (armored or not) and
#    list_players() interprets OpenPGP strings to usable instances.
#    list_players() features a little bit more (detached signature
#    tuples), but is useful to test that sap_out() produces useful
#    strings.
#
#    These tests are kind of a hodgepodge that tries to catch all
#    the possibilities - signature and encrypted message output is
#    handled the same, and they are used to test armoring and
#    compression.
#    """
#    # [txt]/[player] checks unpacking length
#    def testH01OutputEncrypted(self):
#        "sap.api: sap_out() encrypted message, no compression, no armor"
#        fname = sepjoin([curdir,'pgpfiles','enc','sap.2DSAELG1RSA.nocomp.gpg'])
#        fdata = file(fname, 'rb').read()
#        msg = list_msgs(list_pkts(fdata))[0]
#        [txt] = sap_out(msg, 'default', False) # explicitly set native
#        [player] = list_players(txt['data'], None)
#        self.assertEqual(msg.rawstr(), player.rawstr())
#        self.assertEqual('default', txt['name'])
#
#    def testH02OutputEncryptedZIP(self):
#        "sap.api: sap_out() encrypted message, with ZIP, ASCII-armored"
#        _d = read_test_file(['pgpfiles','enc','sap.DSAELG1.zip.gpg'])
#        msg = list_msgs(list_pkts(_d))[0]
#        [txt] = sap_out(msg, 'default') # armor by default
#        [player] = list_players(txt['data'], None)
#        self.assertEqual(msg.rawstr(), player.rawstr())
#        self.assertEqual('default', txt['name'])
#
#    def testH03OutputSignedMsg(self):
#        "sap.api: sap_out() signed message, ASCII-armored"
#        _d = read_test_file(['pgpfiles','sig','sig.RSA1.onepass.gpg'])
#        msg = list_msgs(list_pkts(_d))[0]
#        [txt] = sap_out(msg, 'default', True)
#        [player] = list_players(txt['data'], None)
#        self.assertEqual(msg.rawstr(), player.rawstr())
#        self.assertEqual('default', txt['name'])
#
#    # 'dummy_d' used to create tuple (sigpkt, sigdata) ..obviously bad sigdata
#    def testH03OutputDetachedSignature(self):
#        "sap.api: sap_out() detached signature, ASCII-armored"
#        _d = read_test_file(['pgpfiles','sig','sig.DSAELG1.detached.gpg'])
#        pkt = list_pkts(_d)[0]
#        [txt] = sap_out(pkt, 'default', True)
#        [player] = list_players(txt['data'], 'dummy_d')
#        self.assertEqual(pkt.rawstr(), player[0][0].rawstr())
#        self.assertEqual('default', txt['name'])
#
#    # again, [fd1, fd2] enforces dictionary count
#    def testH04OutputLiteralMsg(self):
#        "sap.api: sap_out() literal message (two files)"
#        f1 = sepjoin([curdir,'pgpfiles','enc','sap.DSAELG1.zip.gpg']) # arbitrary files
#        f1_file = file(f1, 'rb')
#        f1_data = f1_file.read()
#        f2 = sepjoin([curdir,'pgpfiles','enc','sap.DSAELG1.zlib.gpg'])
#        f2_file = file(f2, 'rb')
#        f2_data = f2_file.read()
#        msg = targets2literalmsg([f1_file, f2_file], 'b')
#        [fd1, fd2] = sap_out(msg, 'default')
#        # equal data
#        self.assertEqual(f1_data, fd1['data'])
#        self.assertEqual(f2_data, fd2['data'])
#        # equal filenames
#        self.assertEqual('default.'+os.path.basename(f1), fd1['name'])
#        self.assertEqual('default.'+os.path.basename(f2), fd2['name'])


class COOKeyBlockVerification(unittest.TestCase):
#class COOKeyBlockVerification:
    """sap block verification
    """
    def testC01VerifyKeyBindings(self):
        """verify_block() DSA test for success"""
        key_d = read_test_file(['pgpfiles','key','DSAELG1.pub.gpg'])
        keymsg = list_msgs(list_pkts(key_d))[0]
        # primary block     
        self.assertEqual(True, verify_block(keymsg, 'key', keymsg.primary_id))
        # subkey blocks
        for keyid in keymsg._b_subkeys:
            self.assertEqual(True, verify_block(keymsg, 'key', keyid))

    def testC02VerifyPrimaryKeyBlockLocalRevocation(self):
        """verify_block() catch revoked primary key"""
        key_d = read_test_file(['pgpfiles','key','DSAELG1.pub.revoked.gpg'])
        keymsg = list_msgs(list_pkts(key_d))[0]
        # primary key has been revoked
        r = []
        v = verify_block(keymsg, 'key', keymsg.primary_id, revocs=r)
        self.assertEqual(None, v)
        # get the effective revocation
        sig = r[0]
        self.assertEqual(sig.body.type, 0x20) # SIG_KEYREVOC
        self.assertEqual(sig.body.keyid, keymsg.primary_id)

    def testC03VerifySubkeyBlockLocalRevocation(self):
        """verify_block() catch revoked subkey"""
        key_d = read_test_file(['pgpfiles','key','DSAELG2.subkeyrevoc.gpg'])
        keymsg = list_msgs(list_pkts(key_d))[0]
        r = []
        # we just know this particular key has been revoked
        subkeyid = '90AFB828686B6E9A'
        self.assertEqual(None, verify_block(keymsg, 'key', subkeyid, revocs=r))
        sig = r[0]
        self.assertEqual(sig.body.type, 0x28) # SIG_SUBKEYREVOC
        self.assertEqual(sig.body.keyid, keymsg.primary_id)

    def testC04VerifyPrimaryBlockForeignRevocation(self):
        """verify_block() note subkey revocation by foreign key"""
        key_d = read_test_file(['pgpfiles','key','DSAELG1.pub.foreign_revoked.gpg'])
        keypkts = list_pkts(key_d)
        keymsg = list_msgs(keypkts)[0]
        p = []
        # we just know this particular key has been revoked
        self.assertEqual(True, verify_block(keymsg, 'key', keymsg.primary_id, revocs=p))
        sig = p[0]
        self.assertEqual(sig.body.type, 0x20) # SIG_KEYREVOC
        # make sure that the subpacket foreign key ID matches the fingerprint
        # in the subpacket granted revocation permission
        desig_fingerprint = keypkts[2].body.hashed_subpkts[1].value[2]
        self.assertEqual(desig_fingerprint[-16:], sig.body.keyid)

    def testC05VerifyUserIDBlockLocalRevocation(self):
        "verify_block() catch revoked user ID"
        key_d = read_test_file(['pgpfiles','key','DSAELG2.revoked_uid.gpg'])
        keymsg = list_msgs(list_pkts(key_d))[0]
        r = []
        # we just know this particular key has been revoked
        user_id = 'newuserid' # substring
        self.assertEqual(None, verify_block(keymsg, 'userid', user_id, revocs=r))
        sig = r[0]
        self.assertEqual(sig.body.type, 0x30) 
        self.assertEqual(sig.body.keyid, keymsg.primary_id)


class C01SignatureVerificationTests(unittest.TestCase):
#class C01SignatureVerificationTests:
    """sap Signature Tests
    """

    def xtestC99VerifyPrimaryBlockExpired(self):
        "verify_block() catch expired primary key"
    def xtestC99VerifyPrimaryBlockExpired(self):
        "verify_block() catch expired subkey"

    def testC03DSASignedOnePass(self):
        "verify_msg() DSA one-pass signature as (sigmsg)"
        sig_d = read_test_file(['pgpfiles','sig','sig.DSAELG1.onepass.gpg'])
        key_d = read_test_file(['pgpfiles','key','DSAELG1.pub.gpg'])
        keymsg = list_msgs(list_pkts(key_d))[0]
        sigmsg = list_msgs(list_pkts(sig_d))[0]
        self.assertEqual(sigmsg.msg, verify_msg(sigmsg, keymsg))

    def testC03_1DSASignedOnePass(self):
        "verify_msg() DSA one-pass signature as ([sigs], msg)"
        sig_d = read_test_file(['pgpfiles','sig','sig.DSAELG1.onepass.gpg'])
        key_d = read_test_file(['pgpfiles','key','DSAELG1.pub.gpg'])
        keymsg = list_msgs(list_pkts(key_d))[0]
        sigmsg = list_msgs(list_pkts(sig_d))[0]
        self.assertEqual(sigmsg.msg, verify_msg((sigmsg.sigs, sigmsg.msg), keymsg))

    def testC03_99DSASignedOnePass(self):
        "verify_msg() DSA one-pass signature failure (mismatched key message)"
        sig_d = read_test_file(['pgpfiles','sig','sig.DSAELG1.onepass.gpg'])
        key_d = read_test_file(['pgpfiles','key','RSA1.pub.gpg'])
        keymsg = list_msgs(list_pkts(key_d))[0]
        sigmsg = list_msgs(list_pkts(sig_d))[0]
        self.assertEqual(None, verify_msg((sigmsg.sigs, sigmsg.msg), keymsg))

    def testC04DSADetached(self):
        "verify_msg() DSA detached signature"
        sig_d = read_test_file(['pgpfiles','sig','sig.DSAELG1.detached.gpg'])
        det_d = read_test_file(['pgpfiles','cleartext.txt'])
        key_d = read_test_file(['pgpfiles','key','DSAELG1.pub.gpg'])
        sigpkt = list_pkts(sig_d)[0]
        keymsg = list_msgs(list_pkts(key_d))[0]
        self.assertEqual(det_d, verify_msg(([sigpkt], det_d), keymsg))


class D00DecryptionTests(unittest.TestCase): 
#class D00DecryptionTests: 
    """sap Decryption Tests
    """
    def testD01DecryptPublicELG_CAST(self):
        "decrypt_msg() ElGamal secret key (no pass) CAST compressed"
        enc_d = read_test_file(['pgpfiles','enc','pub.elg.cast.clrtxt.gpg'])
        key_d = read_test_file(['pgpfiles','key','DSAELG1.sec.nopass.gpg'])
        clr_d = read_test_file(['pgpfiles','cleartext.txt'])
        encmsg = list_msgs(list_pkts(enc_d))[0]
        keymsg = list_msgs(list_pkts(key_d))[0]
        compmsg = decrypt_msg(encmsg, key=keymsg)
        litpkt = list_pkts(compmsg.compressed.body.data)[0]
        self.assertEqual(litpkt.body.data, clr_d)

    def testD02DecryptPublicELG_AES256(self):
        "decrypt_msg ElGamal AES256 compressed"
        enc_d = read_test_file(['pgpfiles','enc','pub.elg.aes256.clrtxt.gpg'])
        key_d = read_test_file(['pgpfiles','key','DSAELG1.sec.gpg'])
        clr_d = read_test_file(['pgpfiles','cleartext.txt'])
        encmsg = list_msgs(list_pkts(enc_d))[0]
        keymsg = list_msgs(list_pkts(key_d))[0]
        compmsg = decrypt_msg(encmsg, passphrase='test', key=keymsg)
        litpkt = list_pkts(compmsg.compressed.body.data)[0]
        self.assertEqual(litpkt.body.data, clr_d)

    def testD03DecryptPublicRSA_3DES(self):
        "decrypt_msg() RSA secret key (no pass) 3DES compressed"
        enc_d = read_test_file(['pgpfiles','enc','pub.pgp653rsa.clrtxt.gpg'])
        key_d = read_test_file(['pgpfiles','key','pgp653rsa.sec.nopass.gpg'])
        clr_d = read_test_file(['pgpfiles','cleartext.txt'])
        encmsg = list_msgs(list_pkts(enc_d))[0]
        keymsg = list_msgs(list_pkts(key_d))[0]
        compmsg = decrypt_msg(encmsg, key=keymsg)
        litpkt = list_pkts(compmsg.compressed.body.data)[0]
        self.assertEqual(litpkt.body.data, clr_d)

    def testD04DecryptSymmetricCAST(self):
        "decrypt_msg() symmetric CAST compressed"
        enc_d = read_test_file(['pgpfiles','enc','sym.cast.cleartext.txt.gpg'])
        clr_d = read_test_file(['pgpfiles','cleartext.txt'])
        encmsg = list_msgs(list_pkts(enc_d))[0]
        compmsg = decrypt_msg(encmsg, passphrase='test')
        litpkt = list_pkts(compmsg.compressed.body.data)[0]
        self.assertEqual(litpkt.body.data, clr_d)

    def testD05DecryptSymmetricMDC(self):
        "decrypt_msg() symmetric CAST MDC compressed"
        enc_d = read_test_file(['pgpfiles','enc','mdc.14.212.136.clrtxt.gpg'])
        clr_d = read_test_file(['pgpfiles','cleartext.txt'])
        encmsg = list_msgs(list_pkts(enc_d))[0]
        compmsg = decrypt_msg(encmsg, passphrase='test')
        litpkt = list_pkts(compmsg.compressed.body.data)[0]
        self.assertEqual(litpkt.body.data, clr_d)

    def testD06DecryptMessageSinglePublic(self):
        "decrypt_msg() public key encrypted (by hand)"
        key_d = read_test_file(['pgpfiles','key','DSAELG1.pub.gpg'])
        keypkt = list_pkts(key_d)[3] # ElGamal encrypting key
        d = "My secret message."
        # literal data packet
        litbody = create_LiteralDataBody(data=d, modified=0, format='b',
                                             filename='outfile')
        litpkt = create_Packet(PKT_LITERAL, litbody._d)
        # compressed data packet
        compbody = create_CompressedDataBody(COMP_ZIP, litpkt.rawstr())
        comppkt = create_Packet(PKT_COMPRESSED, compbody._d)
        # session key
        key = gen_random(_keysize(SYM_DES3))
        sespkt = encrypt_public_session(keypkt, key, SYM_DES3)
        # encrypted data
        encpkt = encrypt_integrity(SYM_DES3, key, comppkt.rawstr())
        # make a message
        encmsg = list_msgs([sespkt, encpkt])[0]
        # decryption
        seckey_d = read_test_file(['pgpfiles','key','DSAELG1.sec.nopass.gpg'])
        seckeymsg = list_msgs(list_pkts(seckey_d))[0]
        compmsg = decrypt_msg(encmsg, key=seckeymsg) # no passphrase
        litpkt_out = list_pkts(compmsg.compressed.body.data)[0]
        self.assertEqual(d, litpkt_out.body.data)
        self.assertEqual('outfile', litpkt_out.body.filename)
        self.assertEqual(0, litpkt_out.body.modified)
        self.assertEqual('b', litpkt_out.body.format)


class E00EncryptionTests(unittest.TestCase):
#class E00EncryptionTests:
    """sap Encryption Tests
    """
    # This is just the hand-made test above using encrypt_msg().
    # Oh yeah - use create_literal_message to pass literal data.
    def testE01EncryptSinglePublicNoCompression(self):
        "encrypt_msg()/decrypt_msg() single DSA, ElGamal - no pass"
        key_d = read_test_file(['pgpfiles','key','DSAELG1.pub.gpg'])
        keymsg = list_msgs(list_pkts(key_d))[0]
        d = "My secret message."
        litmsg = create_LiteralMsg({'data':d})
        # target list of keys to encrypt to
        encmsg = encrypt_msg(litmsg, keys=[(keymsg, ['CB7D6980A1F2BEF6'])])  
        # decryption
        seckey_d = read_test_file(['pgpfiles','key','DSAELG1.sec.nopass.gpg'])
        seckeymsg = list_msgs(list_pkts(seckey_d))[0]
        m = decrypt_msg(encmsg, key=seckeymsg)
        compmsg = decrypt_msg(encmsg, key=seckeymsg)
        lit_d = compmsg.compressed.body.data
        litmsg = list_msgs(list_pkts(lit_d))[0]
        self.assertEqual(d, litmsg.literals[0].body.data)

    # Same as above.
    def testE02EncryptSinglePublicZLIB(self):
        "encrypt_msg()/decrypt_msg single DSA, ElGamal - ZLIB compression"
        key_d = read_test_file(['pgpfiles','key','DSAELG1.pub.gpg'])
        keymsg = list_msgs(list_pkts(key_d))[0]
        d = "My secret message."
        litmsg = create_LiteralMsg({'data':d})
        # target list of keys to encrypt to
        opts = {}
        encmsg = encrypt_msg(litmsg, keys=[(keymsg, ['CB7D6980A1F2BEF6'])])  
        # decryption
        seckey_d = read_test_file(['pgpfiles','key','DSAELG1.sec.gpg'])
        seckeymsg = list_msgs(list_pkts(seckey_d))[0]
        compmsg = decrypt_msg(encmsg, passphrase='test', key=seckeymsg)
        litpkt_out = list_pkts(compmsg.compressed.body.data)[0]
        self.assertEqual(d, litpkt_out.body.data)

    # DSAELG3 wants no compression
    def testE03EncryptMultiplePublic(self):
        "encrypt_msg()/decrypt_msg() ElGamal & RSA"
        key_d1 = read_test_file(['pgpfiles','key','DSAELG1.pub.gpg'])
        keymsg1 = list_msgs(list_pkts(key_d1))[0]
        seckey_d1 = read_test_file(['pgpfiles','key','DSAELG1.sec.gpg'])
        seckeymsg1 = list_msgs(list_pkts(seckey_d1))[0]
        ###
        # DSAELG3 was removed because the private encryption key was not bound
        # to the private primary. The result is that the encryption key simply
        # does not register as part of the secret key message at all (it's
        # a leftover).
        #key_d2 = read_test_file(['pgpfiles','key','DSAELG3.pub.gpg'])
        #keymsg2 = list_msgs(list_pkts(key_d2))[0]
        #seckey_d2 = read_test_file(['pgpfiles','key','DSAELG3.sec.nopass.gpg'])
        #seckeymsg2 = list_msgs(list_pkts(seckey_d2))[0]
        key_d3 = read_test_file(['pgpfiles','key','RSA1.pub.gpg'])
        keymsg3 = list_msgs(list_pkts(key_d3))[0]
        seckey_d3 = read_test_file(['pgpfiles','key','RSA1.sec.gpg'])
        seckeymsg3 = list_msgs(list_pkts(seckey_d3))[0]
        d = "My secret message."
        litmsg = create_LiteralMsg({'data':d})
        # target list of keys to encrypt to
        targets = [(keymsg1, ['CB7D6980A1F2BEF6']),
                   #(keymsg2, ['71345307625343E8']),
                   (keymsg3, ['1AC964878A17BAC6'])] # RSA sign/encrypt
        encmsg = encrypt_msg(litmsg, keys=targets)  
        passphrase = 'test'
        # make sure each key can decrypt the message 
        for seckeymsg in [seckeymsg1, seckeymsg3]:
            compmsg = decrypt_msg(encmsg, passphrase='test', key=seckeymsg)
            litmsg = decrypt_msg(encmsg, passphrase='test', key=seckeymsg)
            lit_d = compmsg.compressed.body.data
            litmsg = list_msgs(list_pkts(lit_d))[0]
            self.assertEqual(d, litmsg.literals[0].body.data)
    
    def testE04EncryptDefault(self):
        "encrypt_msg()/decrypt_msg() symmetric"
        d = "My secret message."
        literal_data = {'data':d}
        lit = create_LiteralMsg(literal_data)
        # target list of keys to encrypt to
        encmsg = encrypt_msg(lit, passphrase=None)  
        # decryption, no passphrase
        litmsg = decrypt_msg(encmsg)
        self.assertEqual(d, litmsg.literals[0].body.data)


class F00SigningTests(unittest.TestCase):
    """sap Signature Tests
    """
    def testF01SignRSABinary(self):
        """sign_msg()/verify_msg() RSA binary (0x00)"""
        seckey_d = read_test_file(['pgpfiles','key','RSA1.sec.gpg'])
        seckeymsg = list_msgs(list_pkts(seckey_d))[0]
        passphrase = 'test'
        literal_data = {'data':'An\r\nabnormal\r\r\nsigned\nmessage.\n'}
        lit = create_LiteralMsg(literal_data)
        sigtype = 0x00 # SIG_BINARY
        created = int(time.time()) - 100
        signerid = seckeymsg.primary_id
        opts = {'target':lit,
                'passphrase':passphrase,
                'hashed':[(0x02, created)],
                'unhashed':[(0x10, signerid)]}
        # create signature
        sigmsg = sign_msg(sigtype, seckeymsg, **opts)
        # verify signature
        key_d = read_test_file(['pgpfiles','key','RSA1.pub.gpg'])
        keymsg = list_msgs(list_pkts(key_d))[0]
        self.assertEqual(sigmsg.msg, verify_msg(sigmsg, keymsg))

    def testF02SignRSABinaryDetach(self):
        """sign_msg()/verify_msg() RSA binary (0x00) detached"""
        seckey_d = read_test_file(['pgpfiles','key','RSA1.sec.gpg'])
        seckeymsg = list_msgs(list_pkts(seckey_d))[0]
        passphrase = 'test'
        literal_data = {'data':'An\r\nabnormal\r\r\nsigned\nmessage.\n'}
        lit = create_LiteralMsg(literal_data)
        sigtype = 0x00 # SIG_BINARY
        created = int(time.time()) - 100
        signerid = seckeymsg.primary_id
        opts = {'target':lit,
                'passphrase':passphrase,
                'hashed':[(0x02, created)],
                'unhashed':[(0x10, signerid)],
                'detach':True}
        # create signature
        sigpkt = sign_msg(sigtype, seckeymsg, **opts)
        # verify signature
        key_d = read_test_file(['pgpfiles','key','RSA1.pub.gpg'])
        keymsg = list_msgs(list_pkts(key_d))[0]
        self.assertEqual(lit, verify_msg(([sigpkt], lit), keymsg))

    def testF03SignDSAText(self):
        """sign_msg()/verify_msg() DSA text (0x01)"""
        seckey_d = read_test_file(['pgpfiles','key','DSAELG1.sec.gpg'])
        seckeymsg = list_msgs(list_pkts(seckey_d))[0]
        passphrase = 'test'
        literal_data = {'data':'An\r\nabnormal\r\r\nsigned\nmessage.\n'}
        lit = create_LiteralMsg(literal_data)
        sigtype = 0x01 # SIG_TEXT
        created = int(time.time()) - 100
        signerid = seckeymsg.primary_id
        opts = {'target':lit,
                'passphrase':passphrase,
                'hashed':[(0x02, created)],
                'unhashed':[(0x10, signerid)]}
        # create signature
        sigmsg = sign_msg(sigtype, seckeymsg, **opts)
        # verify signature
        key_d = read_test_file(['pgpfiles','key','DSAELG1.pub.gpg'])
        keymsg = list_msgs(list_pkts(key_d))[0]
        self.assertEqual(sigmsg.msg, verify_msg(sigmsg, keymsg))

    def testF04Unassigned(self):
        "sign_msg()/verify_msg() discover & verify unassigned"
        seckey_d = read_test_file(['pgpfiles','key','DSAELG1.sec.gpg'])
        seckeymsg = list_msgs(list_pkts(seckey_d))[0]
        passphrase = 'test'
        literal_data = {'data':'An\r\nabnormal\r\r\nsigned\nmessage.\n'}
        lit = create_LiteralMsg(literal_data)
        sigtype = 0x01 # SIG_TEXT
        created = int(time.time()) - 100
        opts = {'target':lit,
                'passphrase':passphrase} # no signing keyid
        # create signature
        sigmsg = sign_msg(sigtype, seckeymsg, **opts)
        # verify signature
        key_d = read_test_file(['pgpfiles','key','DSAELG1.pub.gpg'])
        keymsg = list_msgs(list_pkts(key_d))[0]
        self.assertEqual(sigmsg.msg, verify_msg(sigmsg, keymsg))
    
    def testF05_assert_signer(self):
        "sign_msg()/verify_msg() XXX assert signer XXX"
        # 3rd subkey is RSA encrypt or sign
        seckey_d = read_test_file(['pgpfiles','key','DSAELG2.sec.asc'])
        seckeymsg = list_msgs(list_pkts(seckey_d))[0]
        key_d = read_test_file(['pgpfiles','key','DSAELG2.pub.foreign_uid_cert.gpg'])
        keymsg = list_msgs(list_pkts(key_d))[0]
        passphrase = 'test'
        literal_data = {'data':'An\r\nabnormal\r\r\nsigned\nmessage.\n'}
        lit = create_LiteralMsg(literal_data)
        sigtype = 0x00 # SIG_BINARY
        created = int(time.time()) - 100
        opts = {'target':lit, # no signing keyid, make sure no default
                'passphrase':passphrase,
                'use_key':"B45D57C94A595CEE"}
        # this could be split into several tests.. but for now..
        sigmsg = sign_msg(sigtype, seckeymsg, **opts)
        # 1) with no signer asserted, check that the signing key is auto-found
        self.assertEqual(sigmsg.msg, verify_msg(sigmsg, keymsg))
        # 2) with no signer asserted, check that the explicit fprint works this
        # doesn't look much different from the next one, but is needed to make
        # sure it works at all (see the third test)
        f = "4719F5594D9425027F66504AB45D57C94A595CEE"
        self.assertEqual(sigmsg.msg, verify_msg(sigmsg, keymsg, signer_fprint=f))
        # 3) assert WRONG signer ID, but check against explicit fprint
        opts['hashed'] = [(0x10, "6246EF319AC13CFC")] # wrong signer
        sigmsg = sign_msg(sigtype, seckeymsg, **opts)
        self.assertEqual(sigmsg.msg, verify_msg(sigmsg, keymsg, signer_fprint=f))
        # 4) assert WRONG signer ID, let run as normal (no fprint), should fail
        try:
            verify_msg(sigmsg, keymsg)
        except PGPCryptoError:
            pass
        else:
            self.fail()


class G00KeySigningTests(unittest.TestCase):
#class G00KeySigningTests:
    """
    """
    def testG01SignDSADirectNotationDetached(self):
        """sign_msg() DSA direct (0x1F) w/ detached notation"""
        seckey_d = read_test_file(['pgpfiles','key','DSAELG1.sec.gpg'])
        seckeymsg = list_msgs(list_pkts(seckey_d))[0]
        key_d = read_test_file(['pgpfiles','key','DSAELG1.pub.gpg'])
        keymsg = list_msgs(list_pkts(key_d))[0]
        passphrase = 'test'
        sigtype = 0x1F # SIG_DIRECT
        created = int(time.time()) - 100
        signerid = keymsg.primary_id
        opts = {'target':keymsg,
                'passphrase':passphrase,
                'hashed':[(0x02, created),
                          (0x14, (None, 'notename', 'noteval'))], # notation
                'unhashed':[(0x10, signerid)],
                'use_key':signerid,
                'detach':True}
        # create signature on primary key
        sigpkt = sign_msg(sigtype, seckeymsg, **opts)
        # verify signature
        # remember that sign_msg() *applied* the signature packet
        self.assertEqual(keymsg, verify_msg(([sigpkt], keymsg), keymsg))

    def testG02SignDSADirectNotationOnKeyMsg(self):
        """sign_msg() DSA direct (0x1F) on key message"""
        seckey_d = read_test_file(['pgpfiles','key','DSAELG1.sec.gpg'])
        seckeymsg = list_msgs(list_pkts(seckey_d))[0]
        key_d = read_test_file(['pgpfiles','key','DSAELG1.pub.gpg'])
        keymsg = list_msgs(list_pkts(key_d))[0]
        passphrase = 'test'
        sigtype = 0x1F # SIG_DIRECT
        created = int(time.time()) - 100
        signerid = seckeymsg.primary_id
        opts = {'target':keymsg,
                'passphrase':passphrase,
                'hashed':[(0x02, created),
                          (0x14, (None, 'notename', 'noteval'))], # notation
                'unhashed':[(0x10, signerid)],
                'use_key':signerid}
        # create signature on primary key
        updated_keymsg = sign_msg(sigtype, seckeymsg, **opts)
        new_direct_sigpkt = updated_keymsg.seq()[1]
        verified = verify_msg(([new_direct_sigpkt], updated_keymsg),
                                       keymsg)
        self.assertEqual(keymsg, verified)


# local key data
seckey_d = read_test_file(['pgpfiles','key','DSAELG1.sec.gpg'])
key_d = read_test_file(['pgpfiles','key','DSAELG1.pub.gpg'])

class H00LocalKeySignatures(unittest.TestCase):
#class H00LocalKeySignatures:
    """Local "self" signature tests.
    
    - Detached signature packets are used for easier packet comparison.
    - Where possible, I try to get away with assertEqual(sig, keymsg.seq...sig)
      though in real life it won't neccessarily be "equal" as in "the same
      packet" in which case sigpkt.rawstr() is used for comparison.
    - Because encrypt_msg() uses explicit encryption keys as targets,
      it doesn't matter (for the sake of these tests) if a particular user ID
      is being sought or not.
    - key creation times are fixed so the expiration date (creation + expired)
      will eventually run out (whereas signature expirations are relative to
      signatures created on-the-fly during the test). This "shouldn't" be a
      problem since the expiration time was set as high as the field can
      accomodate.
    """
    def setUp(self):
        self.keymsg = list_msgs(list_pkts(key_d))[0]
        self.seckeymsg = list_msgs(list_pkts(seckey_d))[0]
        self.sig_created = int(time.time() - 100)
        self.hashed = [(0x02, self.sig_created)]
        self.unhashed = [(0x10, self.keymsg.primary_id)]
        # detached option makes it easier to check sig attributes & validity
        self.opts = {'target':self.keymsg,
                     'passphrase':"test",
                     'detach':True}

    # all key block verifications should fail w/ effective revoc
    def testH01LocalPrimaryRevoc(self):
        "sign_msg() local revocation (0x20) of primary key"
        sigtype = 0x20
        self.hashed.append((0x1D, (0x00, "No reason.")))
        self.opts['hashed'] = self.hashed
        self.opts['unhashed'] = self.unhashed
        sigpkt = sign_msg(sigtype, self.seckeymsg, **self.opts)
        # all block verifications should fail w/ revocation
        for block in self.keymsg.list_blocks():
            if block.type in [PKT_PUBLICKEY, PKT_PRIVATEKEY, PKT_PUBLICSUBKEY,
                              PKT_PRIVATESUBKEY]:
                revocs = []
                verified = verify_block(self.keymsg, 'key',
                                        block.leader.body.id, revocs=revocs)
                self.assertEqual(None, verified)
                self.assertEqual(revocs[0], sigpkt)
            elif block.type in [PKT_USERID, PKT_USERATTR]:
                revocs = []
                verified = verify_block(self.keymsg, 'userid',
                                        block.leader.body.value, revocs=revocs)
                self.assertEqual(None, verified)
                self.assertEqual(revocs[0], sigpkt)
        # revoc packet will not verify (sign_msg() quirk), effective == same
        revocs2 = []
        verified = verify_msg(([sigpkt], self.keymsg), self.keymsg,
                              revocs=revocs2)
        self.assertEqual(None, verified)
        # diddle sanity tests
        self.assertEqual(revocs, revocs2)
        # revoc packet in place w/ revoc status, reason
        self.assertEqual(sigpkt.body.hashed_subpkts[1].type, 0x1D)
        self.assertEqual(sigpkt.body.hashed_subpkts[1].value, (0x00, "No reason."))
    
    # direct sig should show up in block list and verify
    def testH020LocalPrimaryDirect(self):
        "sign_msg() local direct (0x1F) w/notation on primary key"
        sigtype = 0x1F
        self.hashed.append((20, (None, 'name@test.test', 'notation value')))
        self.opts['hashed'] = self.hashed
        self.opts['unhashed'] = self.unhashed
        sigpkt = sign_msg(sigtype, self.seckeymsg, **self.opts)
        # signature must verify
        verified = verify_msg(([sigpkt], self.keymsg), self.keymsg)
        self.assertEqual(self.keymsg, verified)
        # match signature subpacket info
        self.assertEqual(sigpkt.body.hashed_subpkts[1].type, 0x14)
        self.assertEqual(sigpkt.body.hashed_subpkts[1].value[1], 'name@test.test')
        self.assertEqual(sigpkt.body.hashed_subpkts[1].value[2], 'notation value')
        # signature must be in block
        self.assertEqual(sigpkt, self.keymsg._b_primary.local_direct[0])

    # all key block verifications should fail w/ effective direct 
    def testH021LocalPrimaryDirectExpirationPast(self):
        "sign_msg() local direct (0x1F) on primary key (expired)"
        sigtype = 0x1F
        self.hashed.append((9, 10)) # key expired soon after creation
        self.opts['hashed'] = self.hashed
        self.opts['unhashed'] = self.unhashed
        sigpkt = sign_msg(sigtype, self.seckeymsg, **self.opts)
        # signature should not verify (quirk)
        verified = verify_msg(([sigpkt], self.keymsg), self.keymsg)
        self.assertEqual(None, verified)
        # all block verifications should fail w/ expiration sig
        for block in self.keymsg.list_blocks():
            if block.type in [PKT_PUBLICKEY, PKT_PRIVATEKEY, PKT_PUBLICSUBKEY,
                              PKT_PRIVATESUBKEY]:
                revocs = []
                verified = verify_block(self.keymsg, 'key',
                                        block.leader.body.id, revocs=revocs)
                self.assertEqual(None, verified)
                self.assertEqual(sigpkt, revocs[0])
            elif block.type in [PKT_USERID, PKT_USERATTR]:
                revocs = []
                verified = verify_block(self.keymsg, 'userid',
                                        block.leader.body.value, revocs=revocs)
                self.assertEqual(None, verified)
                self.assertEqual(sigpkt, revocs[0])
        # direct sig should show up
        self.assertEqual(sigpkt, self.keymsg._b_primary.local_direct[0])

    # should not fail, expiration not met
    def testH022LocalPrimaryDirectExpirationPending(self):
        "sign_msg() local direct (0x1F) on primary key (expiration pending)"
        sigtype = 0x1F
        self.hashed.append((9, 4294967295)) # key expires in future
        self.opts['hashed'] = self.hashed
        self.opts['unhashed'] = self.unhashed
        sigpkt = sign_msg(sigtype, self.seckeymsg, **self.opts)
        # signature should verify
        verified = verify_msg(([sigpkt], self.keymsg), self.keymsg)
        self.assertEqual(self.keymsg, verified)
        # all block verifications should verify w/out pending sigs
        for block in self.keymsg.list_blocks():
            if block.type in [PKT_PUBLICKEY, PKT_PRIVATEKEY, PKT_PUBLICSUBKEY,
                              PKT_PRIVATESUBKEY]:
                revocs = []
                verified = verify_block(self.keymsg, 'key',
                                        block.leader.body.id, revocs=revocs)
                self.assertEqual(True, verified)
                self.assertEqual(0, len(revocs))
            elif block.type in [PKT_USERID, PKT_USERATTR]:
                revocs = []
                verified = verify_block(self.keymsg, 'userid',
                                        block.leader.body.value, revocs=revocs)
                self.assertEqual(True, verified)
                self.assertEqual(0, len(revocs))
        # direct sig should show up
        self.assertEqual(sigpkt, self.keymsg._b_primary.local_direct[0])

    # verification of subkey block (only) should fail
    # signing key ID should default to primary
    def testH03LocalSubkeyRevoc(self):
        "sign_msg() local revocation (0x28) of subkey"
        sigtype = 0x28
        self.hashed.append((0x1D, (0x00, "No reason.")))
        self.opts['hashed'] = self.hashed
        self.opts['unhashed'] = self.unhashed
        self.opts['target_key'] = "CB7D6980A1F2BEF6"
        sigpkt = sign_msg(sigtype, self.seckeymsg, **self.opts)
        # revoked block should fail
        verified_block = verify_block(self.keymsg,'key',self.opts['target_key'])
        self.assertEqual(None, verified_block)
        # revoking signature should succeed (no quirks)
        revocs = []
        verified = verify_msg(([sigpkt], self.keymsg), self.keymsg, revocs=revocs)
        self.assertEqual(self.keymsg, verified)
        self.assertEqual(0, len(revocs))
        # encrypting with revoked key should fail
        litmsg = create_LiteralMsg({'data':"binarysig"})
        self.assertRaises(PGPError, encrypt_msg, litmsg,
                          keys=[(self.keymsg, [self.opts['target_key']])])
        # revocation should show up
        self.assertEqual(sigpkt, self.keymsg._b_subkeys[self.opts['target_key']].local_revocs[0])

    # binding should show up in block list and verify
    def testH040LocalSubkeyBinding(self):
        "sign_msg() local binding w/notation (0x18) of subkey"
        sigtype = 0x18
        self.hashed.append((20, (None, 'name@test.test', 'notation value')))
        self.opts['hashed'] = self.hashed
        self.opts['unhashed'] = self.unhashed
        self.opts['target_key'] = "CB7D6980A1F2BEF6"
        sigpkt = sign_msg(sigtype, self.seckeymsg, **self.opts)
        pkt_seq = self.keymsg.seq()
        pkt_seq.pop(4) # get rid of original binding
        keymsg = list_msgs(pkt_seq)[0]
        # binding should verify
        revocs = []
        verified = verify_msg(([sigpkt], keymsg), keymsg, revocs=revocs)
        self.assertEqual(keymsg, verified)
        self.assertEqual(0, len(revocs))
        # block should succeed
        verified_block = verify_block(keymsg, 'key', self.opts['target_key'])
        self.assertEqual(True, verified_block)
        # no exceptions should be raised, so just move along..
        litmsg = create_LiteralMsg({'data':"binarysig"})
        encmsg = encrypt_msg(litmsg, keys=[(keymsg, [self.opts['target_key']])])
        # binding should show up
        self.assertEqual(sigpkt.rawstr(), keymsg._b_subkeys[self.opts['target_key']].local_bindings[0].rawstr())

    # subkey block/use should fail, revocs contains expiration
    def testH041LocalSubkeyBindingExpirationPast(self):
        "sign_msg() local binding (0x18) of subkey (expired)"
        sigtype = 0x18
        self.hashed.append((9, 10)) # key expired soon after creation
        self.opts['hashed'] = self.hashed
        self.opts['unhashed'] = self.unhashed
        self.opts['target_key'] = "CB7D6980A1F2BEF6"
        sigpkt = sign_msg(sigtype, self.seckeymsg, **self.opts)
        # binding should verify
        revocs = []
        verified = verify_msg(([sigpkt], self.keymsg), self.keymsg,
                              revocs=revocs)
        self.assertEqual(self.keymsg, verified)
        self.assertEqual(0, len(revocs))
        # block should fail
        revocs = []
        verified_block = verify_block(self.keymsg, 'key',
                                      self.opts['target_key'], revocs=revocs)
        self.assertEqual(None, verified_block)
        self.assertEqual(sigpkt, revocs[0])
        # encrypting with expired key should fail
        litmsg = create_LiteralMsg({'data':"binarysig"})
        self.assertRaises(PGPError, encrypt_msg, litmsg,
                          keys=[(self.keymsg, [self.opts['target_key']])])
        # binding should show up
        self.assertEqual(sigpkt, self.keymsg._b_subkeys[self.opts['target_key']].local_bindings[1])

    # should not fail, expiration not met, no revocs
    def testH042LocalSubkeyBindingExpirationPending(self):
        "sign_msg() local binding (0x18) of subkey (expiration pending)"
        sigtype = 0x18
        self.hashed.append((9, 1000)) # key expires in future
        self.opts['hashed'] = self.hashed
        self.opts['unhashed'] = self.unhashed
        self.opts['target_key'] = "CB7D6980A1F2BEF6"
        sigpkt = sign_msg(sigtype, self.seckeymsg, **self.opts)
        # binding should verify
        revocs = []
        verified = verify_msg(([sigpkt], self.keymsg), self.keymsg,
                                      revocs=revocs)
        self.assertEqual(self.keymsg, verified)
        self.assertEqual(0, len(revocs))
        # block should succeed
        revocs = []
        verified_block = verify_block(self.keymsg, 'key',
                                      self.opts['target_key'], revocs=revocs)
        self.assertEqual(True, verified_block)
        self.assertEqual(0, len(revocs))
        # encrypting with expired key should succeed
        litmsg = create_LiteralMsg({'data':"binarysig"})
        # no exceptions should be raised, so just move along..
        encmsg = encrypt_msg(litmsg, keys=[(self.keymsg, [self.opts['target_key']])])
        # binding should show up
        self.assertEqual(sigpkt, self.keymsg._b_subkeys[self.opts['target_key']].local_bindings[1])

    # surgery required to construct a key message with an (only an) expired
    # binding
    def testH043LocalSubkeyExpiredBinding(self):
        "sign_msg() expired local binding (0x18) of subkey"
        sigtype = 0x18
        self.hashed.append((3, 10)) # signature has expired
        self.opts['hashed'] = self.hashed
        self.opts['unhashed'] = self.unhashed
        self.opts['target_key'] = "CB7D6980A1F2BEF6"
        sigpkt = sign_msg(sigtype, self.seckeymsg, **self.opts)
        pkt_seq = self.keymsg.seq()
        pkt_seq.pop(4) # ditch original binding, leaving new one ('sigpkt')
        self.assertEqual(sigpkt, pkt_seq[4]) # just to make sure
        keymsg = list_msgs(pkt_seq)[0]
        # binding should fail (signature has expired)
        revocs = []
        verified = verify_msg(([sigpkt], keymsg), keymsg,
                                      revocs=revocs)
        self.assertEqual(None, verified)
        self.assertEqual(0, len(revocs))
        # block should fail (now unbound)
        revocs = []
        verified_block = verify_block(keymsg, 'key', self.opts['target_key'],
                                          revocs=revocs)
        self.assertEqual(None, verified_block)
        self.assertEqual(0, len(revocs))
        # encrypting with expired key should fail
        litmsg = create_LiteralMsg({'data':"binarysig"})
        self.assertRaises(PGPError, encrypt_msg, litmsg,
                          keys=[(keymsg, [self.opts['target_key']])])
        # (expired) binding should show up
        self.assertEqual(sigpkt.rawstr(),
                         keymsg._b_subkeys[self.opts['target_key']].local_bindings[0].rawstr())

    # direct sig should show up in block list and verify, no revocs
    def testH050LocalSubkeyDirect(self):
        "sign_msg() local direct (0x1F) on subkey"
        sigtype = 0x1F
        self.hashed.append((20, (None, 'name@test.test', 'notation value')))
        self.opts['hashed'] = self.hashed
        self.opts['unhashed'] = self.unhashed
        self.opts['target_key'] = "CB7D6980A1F2BEF6"
        sigpkt = sign_msg(sigtype, self.seckeymsg, **self.opts)
        # binding should verify
        revocs = []
        verified = verify_msg(([sigpkt], self.keymsg), self.keymsg,
                                      revocs=revocs)
        self.assertEqual(self.keymsg, verified)
        self.assertEqual(0, len(revocs))
        # block should succeed
        revocs = []
        verified_block = verify_block(self.keymsg, 'key',
                                      self.opts['target_key'], revocs=revocs)
        self.assertEqual(True, verified_block)
        self.assertEqual(0, len(revocs))
        # direct sig should show up
        self.assertEqual(sigpkt, self.keymsg._b_subkeys[self.opts['target_key']].local_direct[0])
        # no exceptions should be raised, the following silence is golden..
        litmsg = create_LiteralMsg({'data':"binarysig"})
        encmsg = encrypt_msg(litmsg, keys=[(self.keymsg, [self.opts['target_key']])])

    # subkey block should fail, revocs holds expiration
    def testH051LocalSubkeyDirectExpirationPast(self):
        "sign_msg() local direct (0x1F) on subkey (expired)"
        sigtype = 0x1F
        self.hashed.append((9, 10)) # key expired soon after creation
        self.opts['hashed'] = self.hashed
        self.opts['unhashed'] = self.unhashed
        self.opts['target_key'] = "CB7D6980A1F2BEF6"
        sigpkt = sign_msg(sigtype, self.seckeymsg, **self.opts)
        # binding should verify
        revocs = []
        verified = verify_msg(([sigpkt], self.keymsg), self.keymsg,
                                      revocs=revocs)
        self.assertEqual(self.keymsg, verified)
        self.assertEqual(0, len(revocs))
        # block should fail
        revocs = []
        verified_block = verify_block(self.keymsg, 'key', self.opts['target_key'],
                                          revocs=revocs)
        self.assertEqual(None, verified_block)
        self.assertEqual(sigpkt, revocs[0])
        # encrypting with expired key should fail
        litmsg = create_LiteralMsg({'data':"binarysig"})
        self.assertRaises(PGPError, encrypt_msg, litmsg,
                          keys=[(self.keymsg, [self.opts['target_key']])])
        # direct sig should show up
        self.assertEqual(sigpkt, self.keymsg._b_subkeys[self.opts['target_key']].local_direct[0])

    # should not fail, expiration not met
    def testH052LocalSubkeyDirectExpirationPending(self):
        "sign_msg() local direct (0x1F) on subkey (expiration pending)"
        sigtype = 0x1F
        self.hashed.append((9, 4294967295)) # key expires in future
        self.opts['hashed'] = self.hashed
        self.opts['unhashed'] = self.unhashed
        self.opts['target_key'] = "CB7D6980A1F2BEF6"
        sigpkt = sign_msg(sigtype, self.seckeymsg, **self.opts)
        # binding should verify
        revocs = []
        verified = verify_msg(([sigpkt], self.keymsg), self.keymsg,
                                      revocs=revocs)
        self.assertEqual(self.keymsg, verified)
        self.assertEqual(0, len(revocs))
        # block should succeed
        revocs = []
        verified_block = verify_block(self.keymsg, 'key', self.opts['target_key'],
                                          revocs=revocs)
        self.assertEqual(True, verified_block)
        self.assertEqual(0, len(revocs))
        # direct sig should show up
        self.assertEqual(sigpkt, self.keymsg._b_subkeys[self.opts['target_key']].local_direct[0])
        # no exceptions should be raised, so just move along..
        litmsg = create_LiteralMsg({'data':"binarysig"})
        encmsg = encrypt_msg(litmsg, keys=[(self.keymsg, [self.opts['target_key']])])

    # block should not verify
    def testH06LocalUserIDRevoc(self):
        "sign_msg() local revocation (0x30) of user ID"
        sigtype = 0x30
        self.opts['hashed'] = self.hashed
        self.opts['unhashed'] = self.unhashed
        self.opts['target_userid'] = self.keymsg._b_userids[0].leader.body.value
        sigpkt = sign_msg(sigtype, self.seckeymsg, **self.opts)
        # binding should verify
        revocs = []
        verified = verify_msg(([sigpkt], self.keymsg), self.keymsg,
                                      revocs=revocs)
        self.assertEqual(self.keymsg, verified)
        self.assertEqual(0, len(revocs))
        # block should fail
        revocs = []
        v = verify_block(self.keymsg, 'userid', self.opts['target_userid'],
                         revocs=revocs)
        self.assertEqual(None, v)
        self.assertEqual(sigpkt, revocs[0])

    # block should verify (pop out original binding)
    def testHO70LocalUserIDCert(self):
        "sign_msg() local certification (0x13) of user ID"
        sigtype = 0x13
        self.opts['hashed'] = self.hashed
        self.opts['unhashed'] = self.unhashed
        self.opts['target_userid'] = self.keymsg._b_userids[0].leader.body.value
        sigpkt = sign_msg(sigtype, self.seckeymsg, **self.opts)
        pkt_seq = self.keymsg.seq()
        pkt_seq.pop(2) # get rid of original binding
        keymsg = list_msgs(pkt_seq)[0]
        # binding should verify
        revocs = []
        verified = verify_msg(([sigpkt], keymsg), keymsg, revocs=revocs)
        self.assertEqual(keymsg, verified)
        self.assertEqual(0, len(revocs))
        # block should succeed
        revocs = []
        verified_block = verify_block(keymsg, 'userid', self.opts['target_userid'],
                                          revocs=revocs)
        self.assertEqual(True, verified_block)
        self.assertEqual(0, len(revocs))

    # block should not verify, only one expired signature is binding
    def testHO71LocalUserIDCertExpirationPast(self):
        "sign_msg() local certification (0x13) of user ID (signature expired)"
        sigtype = 0x13
        self.hashed.append((3, 10)) # signature expired soon after creation
        self.opts['hashed'] = self.hashed
        self.opts['unhashed'] = self.unhashed
        self.opts['target_userid'] = self.keymsg._b_userids[0].leader.body.value
        sigpkt = sign_msg(sigtype, self.seckeymsg, **self.opts)
        pkt_seq = self.keymsg.seq()
        pkt_seq.pop(2) # get rid of original binding
        keymsg = list_msgs(pkt_seq)[0]
        # binding should fail (expired)
        revocs = []
        verified = verify_msg(([sigpkt], keymsg), keymsg, revocs=revocs)
        self.assertEqual(None, verified)
        self.assertEqual(0, len(revocs))
        # block should fail
        revocs = []
        verified_block = verify_block(keymsg, 'userid', self.opts['target_userid'], revocs=revocs)
        self.assertEqual(None, verified_block)
        self.assertEqual(0, len(revocs))

    # block should verify, non-expired binding accompanies expired one
    def testHO72LocalUserIDCertExpirationPastWithOtherGood(self):
        "sign_msg() expired local cert (0x13) + good cert"
        sigtype = 0x13
        self.hashed.append((3, 10)) # signature expired soon after creation
        self.opts['hashed'] = self.hashed
        self.opts['unhashed'] = self.unhashed
        self.opts['target_userid'] = self.keymsg._b_userids[0].leader.body.value
        sigpkt = sign_msg(sigtype, self.seckeymsg, **self.opts)
        # binding should fail (expired)
        revocs = []
        verified = verify_msg(([sigpkt], self.keymsg), self.keymsg, revocs=revocs)
        self.assertEqual(None, verified)
        self.assertEqual(0, len(revocs))
        # block should succeed, since original cert is still good
        revocs = []
        verified_block = verify_block(self.keymsg, 'userid', self.opts['target_userid'], revocs=revocs)
        self.assertEqual(True, verified_block)
        self.assertEqual(0, len(revocs))

    def testHO72LocalUserIDCertExpirationPending(self):
        "sign_msg() local certification (0x10-13) of user ID (signature expiration pending)"
        sigtype = 0x13
        self.hashed.append((3, 1000)) # signature expires in future
        self.opts['hashed'] = self.hashed
        self.opts['unhashed'] = self.unhashed
        self.opts['target_userid'] = self.keymsg._b_userids[0].leader.body.value
        sigpkt = sign_msg(sigtype, self.seckeymsg, **self.opts)
        pkt_seq = self.keymsg.seq()
        pkt_seq.pop(2) # get rid of original binding
        keymsg = list_msgs(pkt_seq)[0]
        # binding should succeed
        revocs = []
        verified = verify_msg(([sigpkt], keymsg), keymsg, revocs=revocs)
        self.assertEqual(keymsg, verified)
        self.assertEqual(0, len(revocs))
        # block should succeed
        revocs = []
        verified_block = verify_block(keymsg, 'userid', self.opts['target_userid'], revocs=revocs)
        self.assertEqual(True, verified_block)
        self.assertEqual(0, len(revocs))


# foreign key data
fseckey_d = read_test_file(['pgpfiles','key','RSA1.sec.gpg'])
fkey_d = read_test_file(['pgpfiles','key','RSA1.pub.gpg'])

class I00ForeignKeySignatures(unittest.TestCase):
#class I00ForeignKeySignatures:
    """Test foreign signatures on a local key message.
    """
    def setUp(self):
        # local key
        self.keymsg = list_msgs(list_pkts(key_d))[0]
        self.seckeymsg = list_msgs(list_pkts(seckey_d))[0]
        self.sig_created = int(time.time() - 100)
        hashed = [(0x02, self.sig_created)]
        # detached option makes it easier to check sig attributes & validity
        self.opts = {'target':self.keymsg,
                     'passphrase':"test",
                     'detach':True,
                     'hashed':hashed}
        # foreign key
        self.fkeymsg = list_msgs(list_pkts(fkey_d))[0]
        self.fseckeymsg = list_msgs(list_pkts(fseckey_d))[0]

    # verifications should all pass, pending revocation should show up
    def testH010ForeignPrimaryRevoc(self):
        "sign_msg() foreign revocation (0x20) of a primary key w/ permission ()"
        # local key message grants revocation permission
        sigtype = 0x1F # direct
        fkeyalg = self.fkeymsg._b_primary.leader.body.alg
        fkeyprint = self.fkeymsg._b_primary.leader.body.fingerprint
        self.opts['hashed'].append((12, (0x80, fkeyalg, fkeyprint)))
        self.opts['unhashed'] = [(0x10, self.keymsg.primary_id)]
        sigpkt = sign_msg(sigtype, self.seckeymsg, **self.opts)
        # foreign key message creates revocation
        self.opts['hashed'].pop() # no need last subpacket
        sigtype = 0x20
        #self.opts['msg'] = self.keymsg
        self.opts['hashed'].append((29, (0x00, "No reason.")))
        self.opts['unhashed'] = [(0x10, self.fkeymsg.primary_id)]
        fsigpkt = sign_msg(sigtype, self.fseckeymsg, **self.opts)
        # primary block should succeed w/ pending revocation
        revocs = []
        verified = verify_block(self.keymsg, 'key', self.keymsg.primary_id,
                                          revocs=revocs)
        self.assertEqual(True, verified)
        self.assertEqual(fsigpkt, revocs[0])
        # pending revocation should verify
        verified = verify_msg(([fsigpkt], self.keymsg), self.fseckeymsg)
        self.assertEqual(self.keymsg, verified)
        # pending revocation in foreign_revocs
        self.assertEqual(fsigpkt, self.keymsg._b_primary.foreign_revocs[0])

    # no key block verifications should fail
    def testH011ForeignPrimaryRevocNoPermission(self):
        "sign_msg() foreign revocation (0x20) of a primary key w/out permission"
        # foreign key message creates revocation
        sigtype = 0x20
        self.opts['hashed'].append((29, (0x00, "No reason.")))
        self.opts['unhashed'] = [(0x10, self.fkeymsg.primary_id)]
        fsigpkt = sign_msg(sigtype, self.fseckeymsg, **self.opts)
        # primary block should succeed w/out pending revocation
        revocs = []
        verified = verify_block(self.keymsg, 'key', self.keymsg.primary_id, revocs=revocs)
        self.assertEqual(True, verified)
        self.assertEqual(0, len(revocs))
        # pending revocation should verify
        verified = verify_msg(([fsigpkt], self.keymsg), self.fkeymsg)
        self.assertEqual(self.keymsg, verified)
        # pending revocation in foreign_revocs
        self.assertEqual(fsigpkt, self.keymsg._b_primary.foreign_revocs[0])

    # show up, verify
    def testH02ForeignPrimaryDirect(self):
        "sign_msg() foreign direct (0x1F) on a primary key"
        sigtype = 0x1F
        self.opts['unhashed'] = [(0x10, self.fkeymsg.primary_id)]
        self.opts['hashed'].append((20, (None,
                                         'name@test.test',
                                         'notation value')))
        fsigpkt = sign_msg(sigtype, self.fseckeymsg, **self.opts)
        # foreign direct should verify
        verified = verify_msg(([fsigpkt], self.keymsg), self.fkeymsg)
        # found in foreign_direct
        self.assertEqual(fsigpkt, self.keymsg._b_primary.foreign_direct[0])
        # notation intact
        notation = fsigpkt.body.hashed_subpkts[1].value
        self.assertEqual('name@test.test', notation[1])
        self.assertEqual('notation value', notation[2])

    # block succeeds w/ pending revoc, permission given in local binding
    def testH030ForeignSubkeyRevoc(self):
        "sign_msg() foreign revocation (0x28) of a subkey (additional binding permission)"
        # local key message grants revocation permission
        sigtype = 0x18 # subkey binding
        fkeyalg = self.fkeymsg._b_primary.leader.body.alg
        fkeyprint = self.fkeymsg._b_primary.leader.body.fingerprint
        self.opts['hashed'].append((12, (0x80, fkeyalg, fkeyprint)))
        self.opts['unhashed'] = [(0x10, self.keymsg.primary_id)]
        self.opts['target_key'] = self.keymsg._b_subkeys[0].leader.body.id
        sigpkt = sign_msg(sigtype, self.seckeymsg, **self.opts)
        # foreign key message creates revocation
        sigtype = 0x28 # subkey revocation
        self.opts['hashed'].pop() # ditch revoker permission above
        #    opts['target_key'] remains
        self.opts['hashed'].append((29, (0x00, "No reason.")))
        self.opts['unhashed'] = [(0x10, self.fkeymsg.primary_id)]
        fsigpkt = sign_msg(sigtype, self.fseckeymsg, **self.opts)
        # subkey block should succeed w/ pending revocation
        revocs = []
        verified = verify_block(self.keymsg, 'key', self.opts['target_key'], revocs=revocs)
        self.assertEqual(True, verified)
        self.assertEqual(fsigpkt, revocs[0])
        # pending revocation should verify
        verified = verify_msg(([fsigpkt], self.keymsg), self.fseckeymsg)
        self.assertEqual(self.keymsg, verified)
        # pending revocation in foreign_revocs
        self.assertEqual(fsigpkt,
             self.keymsg._b_subkeys[self.opts['target_key']].foreign_revocs[0])

    # block succeeds w/ pending revoc, permission given in local direct
    def testH031ForeignSubkeyRevoc(self):
        "sign_msg() foreign revocation (0x28) of a subkey (direct permission)"
        # local key message grants revocation permission
        sigtype = 0x1F # direct
        fkeyalg = self.fkeymsg._b_primary.leader.body.alg
        fkeyprint = self.fkeymsg._b_primary.leader.body.fingerprint
        self.opts['hashed'].append((12, (0x80, fkeyalg, fkeyprint)))
        self.opts['unhashed'] = [(0x10, self.keymsg.primary_id)]
        self.opts['target_key'] = self.keymsg._b_subkeys[0].leader.body.id
        sigpkt = sign_msg(sigtype, self.seckeymsg, **self.opts)
        # foreign key message creates revocation
        sigtype = 0x28 # subkey revocation
        self.opts['hashed'].pop() # ditch revoker permission above
        #    opts['target_key'] remains
        self.opts['hashed'].append((29, (0x00, "No reason.")))
        self.opts['unhashed'] = [(0x10, self.fkeymsg.primary_id)]
        fsigpkt = sign_msg(sigtype, self.fseckeymsg, **self.opts)
        # subkey block should succeed w/ pending revocation
        revocs = []
        verified = verify_block(self.keymsg, 'key', self.opts['target_key'], revocs=revocs)
        self.assertEqual(True, verified)
        self.assertEqual(fsigpkt, revocs[0])
        # pending revocation packet should verify
        verified = verify_msg(([fsigpkt], self.keymsg), self.fseckeymsg)
        self.assertEqual(self.keymsg, verified)
        # pending revocation in foreign_revocs
        self.assertEqual(fsigpkt,
             self.keymsg._b_subkeys[self.opts['target_key']].foreign_revocs[0])

    # block should not fail, sig should show up, no pending revocations
    def testH032ForeignSubkeyRevocNoPermission(self):
        "sign_msg() foreign revocation (0x28) of a subkey (no permission)"
        # foreign key message creates revocation
        sigtype = 0x28 # subkey revocation
        self.opts['hashed'].append((29, (0x00, "No reason.")))
        self.opts['unhashed'] = [(0x10, self.fkeymsg.primary_id)]
        self.opts['target_key'] = self.keymsg._b_subkeys[0].leader.body.id
        fsigpkt = sign_msg(sigtype, self.fseckeymsg, **self.opts)
        # subkey block should succeed w/out any pending revocation
        revocs = []
        verified = verify_block(self.keymsg, 'key', self.opts['target_key'], revocs=revocs)
        self.assertEqual(True, verified)
        self.assertEqual(0, len(revocs))
        # pending revocation packet should verify
        verified = verify_msg(([fsigpkt], self.keymsg), self.fseckeymsg, revocs=revocs)
        self.assertEqual(self.keymsg, verified)
        # pending revocation in foreign_revocs
        self.assertEqual(fsigpkt,
             self.keymsg._b_subkeys[self.opts['target_key']].foreign_revocs[0])

    # ?? should show up
    def testH04ForeignSubkeyBinding(self):
        "sign_msg() foreign binding (0x18) of a subkey"
        sigtype = 0x18 # subkey binding 
        self.opts['unhashed'] = [(0x10, self.fkeymsg.primary_id)]
        self.opts['target_key'] = self.keymsg._b_subkeys[0].leader.body.id
        fsigpkt = sign_msg(sigtype, self.fseckeymsg, **self.opts)
        # subkey block should succeed w/out any pending revocation
        revocs = []
        verified = verify_block(self.keymsg, 'key', self.opts['target_key'], revocs=revocs)
        self.assertEqual(True, verified)
        self.assertEqual(0, len(revocs))
        # binding sig packet should verify
        verified = verify_msg(([fsigpkt], self.keymsg), self.fseckeymsg, revocs=revocs)
        self.assertEqual(self.keymsg, verified)
        # shows up in foreign_bindings
        self.assertEqual(fsigpkt,
             self.keymsg._b_subkeys[self.opts['target_key']].foreign_bindings[0])

    # ?? should show up
    def testH05ForeignSubkeyDirect(self):
        "sign_msg() foreign direct (0x1F) on a subkey"
        sigtype = 0x1F # direct
        self.opts['unhashed'] = [(0x10, self.fkeymsg.primary_id)]
        self.opts['target_key'] = self.keymsg._b_subkeys[0].leader.body.id
        fsigpkt = sign_msg(sigtype, self.fseckeymsg, **self.opts)
        # subkey block should succeed w/out any pending revocation
        revocs = []
        verified = verify_block(self.keymsg, 'key', self.opts['target_key'], revocs=revocs)
        self.assertEqual(True, verified)
        self.assertEqual(0, len(revocs))
        # direct sig packet should verify
        verified = verify_msg(([fsigpkt], self.keymsg), self.fseckeymsg, revocs=revocs)
        self.assertEqual(self.keymsg, verified)
        # shows up in foreign_direct
        self.assertEqual(fsigpkt,
             self.keymsg._b_subkeys[self.opts['target_key']].foreign_direct[0])

    # ?? should show up
    def testH06ForeignUserIDCert(self):
        "sign_msg() foreign cerfication (0x13) of a user ID"
        sigtype = 0x13 # uid certification
        self.opts['unhashed'] = [(0x10, self.fkeymsg.primary_id)]
        self.opts['target_userid'] = self.keymsg._b_userids[0].leader.body.value
        fsigpkt = sign_msg(sigtype, self.fseckeymsg, **self.opts)
        # subkey block should succeed w/out any pending revocation
        revocs = []
        verified = verify_block(self.keymsg, 'userid', self.opts['target_userid'], revocs=revocs)
        self.assertEqual(True, verified)
        self.assertEqual(0, len(revocs))
        # certification packet should verify
        verified = verify_msg(([fsigpkt], self.keymsg), self.fseckeymsg, revocs=revocs)
        self.assertEqual(self.keymsg, verified)
        # shows up in foreign_bindings
        self.assertEqual(fsigpkt,
             self.keymsg._b_userids[self.opts['target_userid']].foreign_bindings[0])

    # ?? should show up
    def testH07ForeignUserIDCertRevoc(self):
        "sign_msg() foreign revocation (0x30) of foreign certification (0x13) of a user ID"
        sigtype = 0x13 # uid certification
        self.opts['unhashed'] = [(0x10, self.fkeymsg.primary_id)]
        self.opts['target_userid'] = self.keymsg._b_userids[0].leader.body.value
        fsigpkt = sign_msg(sigtype, self.fseckeymsg, **self.opts)
        sigtype = 0x30 # certification revocation
        rsigpkt = sign_msg(sigtype, self.fseckeymsg, **self.opts)
        # subkey block should succeed w/out any pending revocation
        revocs = []
        verified = verify_block(self.keymsg, 'userid', self.opts['target_userid'], revocs=revocs)
        self.assertEqual(True, verified)
        self.assertEqual(0, len(revocs))
        # certification packet should verify
        verified = verify_msg(([fsigpkt], self.keymsg), self.fseckeymsg, revocs=revocs)
        self.assertEqual(self.keymsg, verified)
        # revocation packet should verify
        verified = verify_msg(([rsigpkt], self.keymsg), self.fseckeymsg, revocs=revocs)
        self.assertEqual(self.keymsg, verified)
        # certification shows up in foreign_bindings
        self.assertEqual(fsigpkt,
             self.keymsg._b_userids[self.opts['target_userid']].foreign_bindings[0])
        # revocation shows up in foreign_revocs
        self.assertEqual(rsigpkt,
             self.keymsg._b_userids[self.opts['target_userid']].foreign_revocs[0])




#class J00KeyUsage(unittest.TestCase):
#    "Test sign-to, verify-from using key messages in various states."
#class K00KeyUsage(unittest.TestCase):
#    "Timestamp issues; foreign revocation after permission expires, etc."

# check uid cert revocation from pgp to make sure it's also doing funky
# "non-sig" method

if '__main__' == __name__:
    unittest.main()
