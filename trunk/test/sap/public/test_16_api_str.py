"sap text-wise API tests"

import os
import unittest
import pickle

# test targets
from openpgp.sap.api import encrypt_str
from openpgp.sap.api import decrypt_str
from openpgp.sap.api import sign_str
from openpgp.sap.api import verify_str

# package help
from openpgp.code import *
from openpgp.sap.exceptions import *
from openpgp.sap.list import list_pkts, list_msgs, list_as_signed
from openpgp.sap.armory import looks_armored, list_armored

# test help
from support import sepjoin, curdir, read_test_file

linesep = os.linesep

class TestA_decrypt_str(unittest.TestCase):
#class TestA_decrypt_str:
    """
    """
    lit_data = "This is some ordinary text.\n"

    def testC01DecryptDSA(self):
        "decrypt_str() DSA AES256 w/integrity"
        enc_d = read_test_file(['pgpfiles','enc','pub.elg.aes256.clrtxt.gpg'])
        key_d = read_test_file(['pgpfiles','key','DSAELG1.sec.asc'])
        clrtxt = decrypt_str(enc_d, passphrase='test', keys=key_d)
        compmsg = list_as_signed(clrtxt)[0]
        literal_pkt = list_pkts(compmsg.compressed.body.data)[0]
        self.assertEqual(self.lit_data, literal_pkt.body.data)
    
    def testC02DecryptDSA_decompression(self):
        "decrypt_str() DSA AES256 w/integrity (decompressed)"
        enc_d = read_test_file(['pgpfiles','enc','pub.elg.aes256.clrtxt.gpg'])
        key_d = read_test_file(['pgpfiles','key','DSAELG1.sec.asc'])
        clrtxt = decrypt_str(enc_d, passphrase='test', keys=key_d,
                                     decompress=True)
        litmsg = list_as_signed(clrtxt)[0] # no compressed msg to go through
        self.assertEqual(self.lit_data, litmsg.literals[0].body.data)
    
    def testC03DecryptDSA_armor(self):
        "decrypt_str() DSA AES256 w/integrity (armored, decompressed)"
        enc_d = read_test_file(['pgpfiles','enc','pub.elg.aes256.clrtxt.gpg'])
        key_d = read_test_file(['pgpfiles','key','DSAELG1.sec.asc'])
        clrtxt = decrypt_str(enc_d, passphrase='test', keys=key_d,
                                     decompress=True, armor=True)
        self.assertEqual(True, looks_armored(clrtxt)) # check armoring
        litmsg = list_as_signed(clrtxt)[0]
        self.assertEqual(self.lit_data, litmsg.literals[0].body.data)

    def testC04DecryptRSA(self):
        "decrypt_str() RSA w/integrity"
        lit_data = "My secret message."
        enc_d = read_test_file(['pgpfiles','enc','sap.2DSAELG1RSA.nocomp.gpg'])
        key_d = read_test_file(['pgpfiles','key','RSA1.sec.asc'])
        clrtxt = decrypt_str(enc_d, passphrase='test', keys=key_d)
        clrmsgs = list_as_signed(clrtxt)
        literal_pkt = clrmsgs[0].literals[0]
        self.assertEqual(lit_data, literal_pkt.body.data)

    def testC05DecryptSymmetricCAST(self):
        "decrypt_str() symmetric CAST w/integrity"
        enc_d = read_test_file(['pgpfiles','enc','sym.cast.cleartext.txt.gpg'])
        clrtxt = decrypt_str(enc_d, passphrase='test')
        clrmsgs = list_as_signed(clrtxt)
        literal_pkt = list_pkts(clrmsgs[0].compressed.body.data)[0]
        self.assertEqual(self.lit_data, literal_pkt.body.data)

    def testC06DecryptSymmetricCASTMessageFailure(self):
        "decrypt_str() symmetric decryption failure (wrong password)"
        lit_d = read_test_file(['pgpfiles','cleartext.txt'])
        enc_d = read_test_file(['pgpfiles','enc','sym.cast.cleartext.txt.gpg'])
        self.assertRaises(PGPCryptoError, decrypt_str, enc_d, passphrase='badpassword')

    def testC07DecryptPublicSessionFailure(self):
        "decrypt_str() public session decryption failure (wrong password)"
        lit_d = read_test_file(['pgpfiles','cleartext.txt'])
        enc_d = read_test_file(['pgpfiles','enc','pub.elg.aes256.clrtxt.gpg'])
        key_d = read_test_file(['pgpfiles','key','DSAELG1.sec.asc'])
        self.assertRaises(PGPCryptoError, decrypt_str, enc_d, keys=key_d, passphrase='badpassword')

    def testC08DecryptWrongKey(self):
        "decrypt_str() public decryption failure (wrong decryption key)"
        lit_d = read_test_file(['pgpfiles','cleartext.txt'])
        enc_d = read_test_file(['pgpfiles','enc','pub.elg.aes256.clrtxt.gpg'])
        key_d = read_test_file(['pgpfiles','key','DSAELG3.sec.asc']) # wrong key
        self.assertRaises(PGPCryptoError, decrypt_str, enc_d, keys=key_d, passphrase='badpassword')


class TestB_encrypt_str(unittest.TestCase):
#class TestB_encrypt_str:
    lit_data = "This is some ordinary text.\n"

    def testF01EncryptPublicUserID(self):
        "encrypt_str()/decrypt_str() ElGamal via user ID"
        pubkey_d = read_test_file(['pgpfiles','key','DSAELG1.pub.asc'])
        seckey_d = read_test_file(['pgpfiles','key','DSAELG1.sec.asc'])
        cphtxt = encrypt_str(self.lit_data,keys=pubkey_d,use_userid=[(None,"Tester")])
        clrtxt = decrypt_str(cphtxt, passphrase="test", keys=seckey_d, decompress=True)
        litmsg = list_as_signed(clrtxt)[0] # auto-decompressed above
        self.assertEqual(self.lit_data, litmsg.literals[0].body.data)

    def testF02EncryptPublicArmor(self):
        "encrypt_str()/decrypt_str() ElGamal via user ID (armored)"
        pubkey_d = read_test_file(['pgpfiles','key','DSAELG1.pub.asc'])
        seckey_d = read_test_file(['pgpfiles','key','DSAELG1.sec.asc'])
        cphtxt = encrypt_str(self.lit_data,keys=pubkey_d,
                             use_userid=[(None,"Tester")], armor=True)
        self.assertEqual(True, looks_armored(cphtxt))

    def testF03EncryptPublicKeyID(self):
        "encrypt_str()/decrypt_str() ElGamal via key ID"
        pubkey_d = read_test_file(['pgpfiles','key','DSAELG1.pub.asc'])
        seckey_d = read_test_file(['pgpfiles','key','DSAELG1.sec.asc'])
        cphtxt = encrypt_str(self.lit_data, keys=pubkey_d, use_key=[(None,"CB7D6980A1F2BEF6")])
        clrtxt = decrypt_str(cphtxt, passphrase="test", keys=seckey_d, decompress=True)
        litmsg = list_as_signed(clrtxt)[0] # auto-decompressed above
        self.assertEqual(self.lit_data, litmsg.literals[0].body.data)
    
    def testF04EncryptPublicKeyIDNoTarget(self):
        "encrypt_str()/decrypt_str() no specified encryption key"
        pubkey_d = read_test_file(['pgpfiles','key','DSAELG1.pub.asc'])
        seckey_d = read_test_file(['pgpfiles','key','DSAELG1.sec.asc'])
        try:
            cphtxt = encrypt_str(self.lit_data, keys=pubkey_d) # missing target
        except PGPError:
            pass
        else:
            self.fail()
        
    def testF05EncryptSymmetric(self):
        "encrypt_str()/decrypt_str() symmetric default"
        cphtxt = encrypt_str(self.lit_data, passphrase="test")
        clrtxt = decrypt_str(cphtxt, passphrase="test", decompress=True)
        litmsg = list_as_signed(clrtxt)[0] # auto-decompressed above
        self.assertEqual(self.lit_data, litmsg.literals[0].body.data)

    # decrypt individually to make sure each uses its own secret key
    # SEE similar test in encrypt_msg()/decrypt_msg() commented out reasons
    def testF06EncryptMultiplePublicUserID(self):
        "encrypt_str()/decrypt_str() multiple public (no compression) via user ID"
        pubkey1_d = read_test_file(['pgpfiles','key','DSAELG1.pub.asc'])
        seckey1_d = read_test_file(['pgpfiles','key','DSAELG1.sec.asc'])
        #pubkey2_d = read_test_file(['pgpfiles','key','DSAELG3.pub.asc'])
        #seckey2_d = read_test_file(['pgpfiles','key','DSAELG3.sec.asc'])
        pubkey3_d = read_test_file(['pgpfiles','key','RSA1.pub.asc'])
        seckey3_d = read_test_file(['pgpfiles','key','RSA1.sec.asc'])
        pubkey_d = linesep.join([pubkey1_d, pubkey3_d])
        uids = [(None,"Tester"),
                #(None,"testdiffhelldss@test.test"),
                (None,"testrsa")]
        cphtxt = encrypt_str(self.lit_data, keys=pubkey_d, use_userid=uids)
        # they all happen to have the same passphrase
        passphrase = "test"
        for seckey_d in [seckey1_d, seckey3_d]:
            clrtxt = decrypt_str(cphtxt, passphrase="test", keys=seckey_d,
                                 decompress=True)
            litmsg = list_as_signed(clrtxt)[0]
            self.assertEqual(self.lit_data, litmsg.literals[0].body.data)


class TestC_verify_str(unittest.TestCase):
#class TestC_verify_str:
    """verify_str()

    Like the ones above, these tests just ensure predictable
    output from `verify_str()`.
    """
    # Because we're working with clearsigned text, the "thing" that was
    # verified was the text (not anything in a literal/compressed). Further,
    # the clearsigned text has trailing lineseps stripped, so there isn't an
    # '\n' at the end of the string like there is in most of the other test
    # cases.
    def testB01VerifyDSAClearsigned(self):
        "verify_str() DSA clearsigned with armored key"
        sig_d = read_test_file(['pgpfiles','sig','sig.DSAELG1.clear.asc'])
        key_d = read_test_file(['pgpfiles','key','DSAELG1.pub.asc'])
        self.assertEqual("This is some ordinary text.", verify_str(sig_d, key_d))

    def testB02VerifyDSANativeOnePass(self):
        "verify_str() DSA one-pass sig (armored output)"
        sig_d = read_test_file(['pgpfiles','sig','sig.DSAELG1.onepass.gpg'])
        key_d = read_test_file(['pgpfiles','key','DSAELG1.pub.asc'])
        armored = verify_str(sig_d, key_d, armor=True)
        self.assertEqual(True, looks_armored(armored))
    
    def testB03VerifyDSADetached(self):
        "verify_str() DSA detached sig with armored key"
        sig_d = read_test_file(['pgpfiles','sig','sig.DSAELG1.detached.gpg'])
        det_d = read_test_file(['pgpfiles','cleartext.txt'])
        key_d = read_test_file(['pgpfiles','key','DSAELG1.pub.asc'])
        self.assertEqual(det_d, verify_str(sig_d, key_d, detached=det_d))

    # signed messages may be hidden inside compressed messages
    def testB04VerifyDSACompressed(self):
        "verify_str() DSA compressed one-pass sig with armored key (native output)"
        lit_d = "\xac/b\rcleartext.txt?\x07+kThis is some ordinary text.\n"
        sig_d = read_test_file(['pgpfiles','sig','sig.DSAELG1.comp.gpg'])
        key_d = read_test_file(['pgpfiles','key','DSAELG1.pub.asc'])
        self.assertEqual(lit_d, verify_str(sig_d, key_d)) # no armoring
    
    # That which was verified did not include the incoming armored headers (in
    # this case, "Version: GnuPG v1.2.2 (GNU/Linux)') ..so the armored output
    # would not match the armored input. The check is made over the key
    # messages found in both.
    def testB05VerifyKey(self):
        "verify_str() verify local key sigs (headers lost in armored output)"
        key_d = read_test_file(['pgpfiles','key','DSAELG1.pub.asc'])
        verified = verify_str(key_d, key_d)
        self.assertEqual(list_as_signed(key_d), list_as_signed(verified))


class TestD_sign_str(unittest.TestCase):
    """
    """
    def testE01SignBinaryAsMsgViaUID(self):
        "sign_str()/verify_str() binary (0x00) using user ID"
        lit_d = read_test_file(['pgpfiles','cleartext.txt'])
        seckey_d = read_test_file(['pgpfiles','key','DSAELG1.sec.asc'])
        pubkey_d = read_test_file(['pgpfiles','key','DSAELG1.pub.asc'])
        signed = sign_str(0x00, seckey_d, target=lit_d,
                          use_userid=(None,'Tester'),
                          passphrase='test')
        verified = verify_str(signed, pubkey_d)
        self.assertEqual(lit_d, list_pkts(verified)[0].body.data)

    def testE02SignTextKeyID(self):
        "sign_str()/verify_str() text (0x01) using key ID"
        lit_d = read_test_file(['pgpfiles','cleartext.txt'])
        seckey_d = read_test_file(['pgpfiles','key','DSAELG1.sec.asc'])
        pubkey_d = read_test_file(['pgpfiles','key','DSAELG1.pub.asc'])
        signed = sign_str(0x01, seckey_d, target=lit_d,
                          use_key=(None, '0CFC2B6DCC079DF3'),
                          passphrase='test')
        verified = verify_str(signed, pubkey_d)
        self.assertEqual(lit_d, list_pkts(verified)[0].body.data)

    def testE03SignDetached(self):
        "sign_str()/verify_str() detached binary (0x00) using key ID"
        lit_d = read_test_file(['pgpfiles','cleartext.txt'])
        seckey_d = read_test_file(['pgpfiles','key','DSAELG1.sec.asc'])
        pubkey_d = read_test_file(['pgpfiles','key','DSAELG1.pub.asc'])
        sigtype = 0x01
        keyid_d = "0CFC2B6DCC079DF3"
        passphrase = "test"
        sigpkt = sign_str(0x01, seckey_d, target=lit_d,
                          use_key=(None, '0CFC2B6DCC079DF3'),
                          passphrase='test',
                          detach=True)
        verified = verify_str(sigpkt, pubkey_d, detached=lit_d)
        self.assertEqual(lit_d, verified)

    def testE04SignSubkey(self):
        "sign_str()/verify_str() subkey direct (0x1F) w/ lots of subpackets"
        seckey_d = read_test_file(['pgpfiles','key','DSAELG1.sec.asc'])
        pubkey_d = read_test_file(['pgpfiles','key','DSAELG1.pub.asc'])
        keyid = "0CFC2B6DCC079DF3"
        opts = {'use_key':(None, keyid),
                'passphrase':"test",
                'target':pubkey_d,
                'target_key':(None,"CB7D6980A1F2BEF6"),
                'sig_signerid':keyid,
                'sig_created':100,
                'sig_expires':4294967295,
                'sig_keyexpires':4294967200,
                'sig_revoker':(0x80,1,"AB06532F70BD5CD68978D0181AC964878A17BAC6"),
                #'sig_note':"n1@test::v1 ,, n2@test:: v2,,n3@test:: v3 ",
                'sig_note':[("n1@test","v1"),("n2@test","v2"),("n3@test","v3")],
                'sig_policyurl':"http://policy.com"}
        #keymsg = sign_str(0x1F, seckey_d, **opts)
        signed = sign_str(0x1F, seckey_d, **opts)
        keymsg = list_as_signed(signed)[0]
        sigpkt = keymsg._b_subkeys['CB7D6980A1F2BEF6'].local_direct[0]
        # the subpkt order is determined by their order of appendage in
        # sign_str() which isn't important, it's just convenient for testing
        h = sigpkt.body.hashed_subpkts 
        [signerid, created, sig_exp, key_exp, n1, n2, n3, url, revoker] = h
        self.assertEqual((0x10, keyid), (signerid.type, signerid.value))
        self.assertEqual((0x02, 100), (created.type, created.value))
        self.assertEqual((0x03, 4294967295), (sig_exp.type, sig_exp.value))
        self.assertEqual((0x09, 4294967200), (key_exp.type, key_exp.value))
        self.assertEqual((0x14, "n1@test", "v1"), (n1.type, n1.value[1], n1.value[2]))
        self.assertEqual((0x14, "n2@test", "v2"), (n2.type, n2.value[1], n2.value[2]))
        self.assertEqual((0x14, "n3@test", "v3"), (n3.type, n3.value[1], n3.value[2]))
        self.assertEqual((0x1A, "http://policy.com"), (url.type, url.value))
        self.assertEqual((0x0C, (128, 1, "AB06532F70BD5CD68978D0181AC964878A17BAC6")), (revoker.type, revoker.value))
        # verify new sig (everything in signed is verified against pubkey_d)
        verified = verify_str(signed, pubkey_d)
        self.assertEqual(verified, signed)

    def testE05SignBinaryAsStringUsingUID(self):
        "sign_str()/verify_str() check literal data options"
        lit_d = read_test_file(['pgpfiles','cleartext.txt'])
        seckey_d = read_test_file(['pgpfiles','key','DSAELG1.sec.asc'])
        pubkey_d = read_test_file(['pgpfiles','key','DSAELG1.pub.asc'])
        signed = sign_str(0x00, seckey_d, target=lit_d,
                          use_userid=(None,'Tester'),
                          passphrase='test',
                          lit_filename='testfilename',
                          lit_modified=100)
        verified = verify_str(signed, pubkey_d) # verified strips sigs..
        literal_body = list_as_signed(verified)[0].literals[0].body
        self.assertEqual('b', literal_body.format)
        self.assertEqual(lit_d, literal_body.data)
        self.assertEqual('testfilename', literal_body.filename)
        self.assertEqual(100, literal_body.modified)

    def testE07SignSubkeyAsStringBadTarget(self):
        "sign_str() subkey direct (0x1F) target not found"
        seckey_d = read_test_file(['pgpfiles','key','DSAELG1.sec.asc'])
        pubkey_d = read_test_file(['pgpfiles','key','DSAELG1.pub.asc'])
        try:
            sigpkt = sign_str(0x1F, seckey_d, target=pubkey_d,
                              use_key=(None, "0CFC2B6DCC079DF3"),
                              target_key=(None,"CB7D6980A1F2BExxx"), # munged
                              passphrase='test')
        except PGPError: # target key is specified so it must be used
            pass
        else:
            self.fail()
    
    def testE08SignSubkeyBadSigner(self):
        "sign_str() subkey direct (0x1F) target not found"
        seckey_d = read_test_file(['pgpfiles','key','DSAELG1.sec.asc'])
        pubkey_d = read_test_file(['pgpfiles','key','DSAELG1.pub.asc'])
        try:
            sigpkt = sign_str(0x1F, seckey_d, target=pubkey_d,
                              use_key=(None, "0CFC2B6DCC079xxx"), # munged
                              target_key=(None,"CB7D6980A1F2BEF6"),
                              passphrase='test')
        except PGPError: # signing key is specified so it must be used
            pass
        else:
            self.fail()


#######################
# MOVE TO CMDLINE STUFF
#    def testF01aEncryptPublicUserIDViaFiles(self):
#        "encrypt_str()/decrypt_str() ElGamal via user ID (via files)"
#        import StringIO # emulate encmsg as file?
#        lit_d = read_test_file(['pgpfiles','cleartext.txt'])
#        pubkey_file = file(sepjoin([curdir,'pgpfiles','key','DSAELG1.pub.asc']), 'rb')
#        seckey_file = file(sepjoin([curdir,'pgpfiles','key','DSAELG1.sec.asc']), 'rb')
#        userid = "Tester"
#        encmsg = encrypt_str(lit_d, pubkey_file, userid)
#        passphrase = "test"
#        encfile = StringIO.StringIO(encmsg.rawstr())
#        compmsg = decrypt_str(encfile, passphrase, seckey_file)[0]
#        pubkey_file.close()
#        seckey_file.close()
#        _d = compmsg.compressed.body.data
#        litmsg = list_msgs(list_pkts(_d))[0]
#        self.assertEqual(lit_d, litmsg.literals[0].body.data)
#
#    def testE01aSignBinaryAsMsgViaUIDUsingFiles(self):
#        "sign_str()/verify_str() binary (0x00) via user ID (using files)"
#        import StringIO
#        lit_file = file(sepjoin([curdir,'pgpfiles','cleartext.txt']),'rb')
#        seckey_file = file(sepjoin([curdir,'pgpfiles','key','DSAELG1.sec.asc']),'rb')
#        pubkey_file = file(sepjoin([curdir,'pgpfiles','key','DSAELG1.pub.asc']),'rb')
#        sigtype = 0x00
#        userid = "Tester"
#        passwd = "test"
#        sigmsg = sign_str(sigtype, lit_file, seckey_file, userid, passwd,
#                              False)
#        sigmsg_file = StringIO.StringIO(sigmsg.rawstr())
#        self.assertEqual(True, verify_str(sigmsg_file, pubkey_file, None))
#        seckey_file.close()
#        pubkey_file.close()
#
#    def testB01aVerifyDSAClearsignedViaFiles(self):
#        "verify_str() DSA clearsigned (+ ASCII-armored key) via files"
#        sig_file = file(sepjoin([curdir,'pgpfiles','sig','sig.DSAELG1.clear.asc']), 'rb')
#        key_file = file(sepjoin([curdir,'pgpfiles','key','DSAELG1.pub.asc']), 'rb')
#        self.assertEqual(True, verify_str(sig_file, key_file, None))
#        sig_file.close()
#        key_file.close()
#    



if '__main__' == __name__:
    unittest.main()
