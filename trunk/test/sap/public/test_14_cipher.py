"""Cipher Tests
"""
import unittest
import os

# test targets
from openpgp.sap.crypto import decrypt_symmetric
from openpgp.sap.crypto import decrypt_symmetric_resync
from openpgp.sap.crypto import decrypt_public
from openpgp.sap.crypto import decrypt
from openpgp.sap.crypto import encrypt_symmetric_session
from openpgp.sap.crypto import encrypt_public_session
from openpgp.sap.crypto import encrypt_integrity
from openpgp.sap.crypto import gen_random
from openpgp.sap.crypto import string2key
from openpgp.sap.crypto import _keysize # ugly
# missing decrypt_secret_key
# missing encrypt_public_session

# package help
from openpgp.code import *
from openpgp.sap.util.strnum import mpilen2int, str2int
from openpgp.sap.armory import list_armored
from openpgp.sap.pkt.Packet import create_Packet
from openpgp.sap.pkt.LiteralData import create_LiteralDataBody
from openpgp.sap.pkt.CompressedData import create_CompressedDataBody
from openpgp.sap.list import list_pkts, list_msgs

# test help
from support import sepjoin, curdir, read_test_file


class B00S2KTests(unittest.TestCase):
    """String-to-Key Tests

    For a given set of string-to-key (s2k) parameters, make sure they create
    the proper key. Since most of the parameters are hidden in the S2K
    instance, they have to be fudged by hand here first. S2K parameters include
    type, hash algorithm, salt, and count (where count is a single byte).
    'string2key()' also needs a cipher type (integer constant) and passphrase
    string to make the key.
    """
    def setUp(self):
        class EmptyS2K: pass
        self.s2k = EmptyS2K()

    def testB01S2Kv3(self):
        """crypto.cipher: S2K type 0x03 (SHA1/CAST5)"""
        self.s2k.type = 0x03
        self.s2k.alg_hash = HASH_SHA1 # SHA1
        self.s2k.salt = '\xd6\xcd\xd8\x35\x70\x06\x22\xdf'
        self.s2k.count = 65536 # corresponds to s2k.count_code = 96 (standard GnuPG)
        ciphertype = SYM_CAST5
        passphrase = 'test'
        testkey = string2key(self.s2k, ciphertype, passphrase)
        goodkey = '\xa5\xba\x8e\x2f\x81\x4a\xee\xa7\xc5\x25\xd6\xeb\x75\x75\xef\x0c'
        self.assertEqual(testkey, goodkey)
        # one more time for good luck
        self.s2k.type = 0x03
        self.s2k.alg_hash = HASH_SHA1 # SHA1
        self.s2k.salt = '\x02\xa5\xec\x54\x32\xbd\xf4\xa8'
        self.s2k.count = 65536 # corresponds to s2k.count_code = 96 (standard GnuPG)
        ciphertype = SYM_CAST5
        passphrase = 'test'
        testkey = string2key(self.s2k, ciphertype, passphrase)
        goodkey = '\xb4\x99\xdc\x1d\x1d\x53\x3c\x8c\x6f\x89\x0b\xe3\x42\xf3\x0e\x73'
        self.assertEqual(testkey, goodkey)


sym_cast_d = read_test_file(['pgpfiles','enc','sym.cast.cleartext.txt.gpg'])

class C00ConventionalDecryption(unittest.TestCase):
    """Conventional Decryption Tests

    Decrypt encrypted OpenPGP packets by hand. These tests operate on
    symmetically (conventionally) encrypted messages that have
    encrypted the contents of 'cleartext.txt'.
    """
    def setUp(self):
        self.cleartext = read_test_file(['pgpfiles','cleartext.txt'])

    def testC01MDCBlowfish(self):
        """crypto.cipher: decrypt_symmetric() Blowfish"""
        # Almost the same, this time with Blowfish and no compressed packet.
        mdc_d = read_test_file(['pgpfiles','enc','mdc.nocompress.blo.254.196.198.clrtxt.gpg'])
        pkts = list_pkts(mdc_d)
        seskey, symint = pkts[0].body, pkts[1].body
        passphrase = 'test'
        key = string2key(seskey.s2k, seskey.alg, passphrase)
        result = decrypt_symmetric(seskey.alg, key, symint.data)
        result = result[10:] # ditching the prefix + 2
        literal = list_pkts(result)[0].body
        self.assertEqual(self.cleartext, literal.data)

    def testC02IntegrityProtectedCAST(self):
        """crypto.cipher: decrypt_symmetric() CAST5"""
        # Same as test above, just wrapped integrity protected packet.
        mdc_d = read_test_file(['pgpfiles','enc','mdc.14.212.136.clrtxt.gpg'])
        pkts = list_pkts(mdc_d)
        seskey, symint = pkts[0].body, pkts[1].body
        passphrase = 'test'
        key = string2key(seskey.s2k, seskey.alg, passphrase)
        result = decrypt_symmetric(seskey.alg, key, symint.data)
        result = result[10:] # ditching the prefix + 2
        compressed = list_pkts(result)[0].body
        comp_d = compressed.data
        literal = list_pkts(comp_d)[0].body
        self.assertEqual(self.cleartext, literal.data)

    def testC03DecryptSymmetricCAST(self):
        """crypto.cipher: decrypt_symmetric_resync() CAST5"""
        # This message is known to have a compressed packet containing a literal
        # packet containing the text from cleartext.txt.
        dektest_d = read_test_file(['pgpfiles','enc','dek.180.153.220.clrtxt.gpg'])
        pkts = list_pkts(dektest_d)
        seskey, enc = [x.body for x in pkts]
        passphrase = 'test'
        key = string2key(seskey.s2k, seskey.alg, passphrase)
        result = decrypt_symmetric_resync(seskey.alg, key, enc.data)
        compressed = list_pkts(result)[0].body
        comp_d = compressed.data
        literal = list_pkts(comp_d)[0].body
        self.assertEqual(self.cleartext, literal.data)
    

class D00SecretKey(unittest.TestCase):
    """Secret Key Tests:
    
    These tests make sure that encrypted secret key material is accessible.
    No self-verification is performed (checksums/hashes), all checks are
    made against known good data. Slice indices of the version 4 cleartext
    MPI data keep all the key octets and dismiss the extra 20 hash octets.
    """
    # Only the first 22 octets of the MPI cleartext is verified, the extra
    # cleartext (20 octets) is a SHA-1 verification.
    def testD01DSASecretKey(self):
        """crypto.cipher: decrypt_symmetric() v4 DSA secret key (DSA_x)"""
        dsasec_d = read_test_file(['pgpfiles','key','DSAELG1.sec.gpg'])
        dsasecnopass_d = read_test_file(['pgpfiles','key','DSAELG1.sec.nopass.gpg'])
        pkts, nopasspkts = list_pkts(dsasec_d), list_pkts(dsasecnopass_d)
        secretkey_pkt, nopasskey_pkt = pkts[0], nopasspkts[0]
        secretkey, nopasskey = secretkey_pkt.body, nopasskey_pkt.body
        passphrase = 'test'
        key = string2key(secretkey.s2k, secretkey.alg_sym, passphrase)
        result = decrypt_symmetric(secretkey.alg_sym, key, secretkey._enc_d, secretkey.iv)
        self.assertEqual(nopasskey.DSA_x._d, result[:22])

    def testD02RSASecretKey(self):
        """crypto.cipher: decrypt_symmetric() v4 RSA secret key (RSA_d,p,q,u)"""
        rsasec_d = read_test_file(['pgpfiles','key','RSA1.sec.gpg'])
        rsasecnopass_d = read_test_file(['pgpfiles','key','RSA1.sec.nopass.gpg'])
        pkts, nopasspkts = list_pkts(rsasec_d), list_pkts(rsasecnopass_d)
        secretkey_pkt, nopasskey_pkt = pkts[0], nopasspkts[0]
        secretkey, nopasskey = secretkey_pkt.body, nopasskey_pkt.body
        passphrase = 'test'
        key = string2key(secretkey.s2k, secretkey.alg_sym, passphrase)
        result = decrypt_symmetric(secretkey.alg_sym, key, secretkey._enc_d, secretkey.iv)
        good_mpi_d = nopasskey.RSA_d._d + nopasskey.RSA_p._d + nopasskey.RSA_q._d + nopasskey.RSA_u._d
        self.assertEqual(good_mpi_d, result[:328])

    # This is all done by hand ~ it is "known" that the secret key data
    # consists of RSA d, p, q, and u MPIs in that order.
    def testD03RSA(self):
        """crypto.cipher: decrypt_symmetric() v3 RSA secret key (RSA_d,p,q,u)"""
        rsasec_armored = read_test_file(['pgpfiles','interop','pgp6.5.3','RSA1','key.pgp6.5.3.RSA1.sec.asc'])
        rsanopass_armored = read_test_file(['pgpfiles','interop','pgp6.5.3','RSA1','key.pgp6.5.3.RSA1.sec.nopass.asc'])
        rsasec_d, rsanopass_d = list_armored(rsasec_armored)[0].data, list_armored(rsanopass_armored)[0].data
        pkts, nopasspkts = list_pkts(rsasec_d), list_pkts(rsanopass_d)
        secretkey_pkt, nopasskey_pkt = pkts[0], nopasspkts[0]
        secretkey, nopasskey = secretkey_pkt.body, nopasskey_pkt.body
        passphrase = 'test'
        # for the future..
        if secretkey.s2k_usg in [254, 255]: # we have an s2k
            key = string2key(secretkey.s2k, secretkey.alg_sym, passphrase)
        else:
            import md5
            key = md5.new(passphrase).digest()
        # Just comparing bytes, not integer values. The funky notation
        # 'enc_RSA_d_d', 'enc_RSA_p_d' means "the encrypted *integer*
        # data from the RSA d and p # MPIs, respectively.
        # 'len_RSA_d_d' means "the octet length of the integer portion
        # of the RSA d MPI."
        idx = 0
        # RSA_d
        len_RSA_d_d = mpilen2int(secretkey._enc_d[idx:idx+2])
        idx = idx + 2
        enc_RSA_d_d = secretkey._enc_d[idx:idx+len_RSA_d_d]
        idx = idx + len_RSA_d_d
        iv = secretkey.iv # iv provided
        RSA_d_d = decrypt_symmetric(secretkey.alg_sym, key, enc_RSA_d_d, iv)
        self.assertEqual(RSA_d_d, nopasskey.RSA_d._int_d)
        # RSA_p
        len_RSA_p_d = mpilen2int(secretkey._enc_d[idx:idx+2])
        idx = idx + 2
        enc_RSA_p_d = secretkey._enc_d[idx:idx+len_RSA_p_d]
        idx = idx + len_RSA_p_d
        iv = enc_RSA_d_d[-8:] # last 8 octets from "pre-sync" instream
        RSA_p_d = decrypt_symmetric(secretkey.alg_sym, key, enc_RSA_p_d, iv)
        self.assertEqual(RSA_p_d, nopasskey.RSA_p._int_d)
        # RSA_q
        len_RSA_q_d = mpilen2int(secretkey._enc_d[idx:idx+2])
        idx = idx + 2
        enc_RSA_q_d = secretkey._enc_d[idx:idx+len_RSA_q_d]
        idx = idx + len_RSA_q_d
        iv = enc_RSA_p_d[-8:] # last 8 octets from "pre-sync" instream
        RSA_q_d = decrypt_symmetric(secretkey.alg_sym, key, enc_RSA_q_d, iv)
        self.assertEqual(RSA_q_d, nopasskey.RSA_q._int_d)
        # RSA_u
        len_RSA_u_d = mpilen2int(secretkey._enc_d[idx:idx+2])
        idx = idx + 2
        enc_RSA_u_d = secretkey._enc_d[idx:idx+len_RSA_u_d]
        idx = idx + len_RSA_u_d
        iv = enc_RSA_q_d[-8:] # last 8 octets from "pre-sync" instream
        RSA_u_d = decrypt_symmetric(secretkey.alg_sym, key, enc_RSA_u_d, iv)
        self.assertEqual(RSA_u_d, nopasskey.RSA_u._int_d)


class E00PublicKeySanity(unittest.TestCase):
    """Public Key Encryption/Decryption Sanity Tests
    """


class F00PublicKeyDecryption(unittest.TestCase):
    """Public Key Decryption
    """
    def testF01ElGamal(self):
        """crypto.cipher: decrypt_public() ElGamal-encrypted session key"""
        #encmsg_d = read_test_file(['pgpfiles','enc','pub.elg.aes256.clrtxt.gpg'])
        encmsg_d = read_test_file(['pgpfiles','enc','pub.elg.cast.clrtxt.gpg'])
        encmsg = list_msgs(list_pkts(encmsg_d))[0]
        seskeypkt = encmsg.targets[0] # target = session key 
        # get target secret key (in this case, a subkey)
        keymsg_d = read_test_file(['pgpfiles','key','DSAELG1.sec.nopass.gpg'])
        keymsg = list_msgs(list_pkts(keymsg_d))[0]
        for block in keymsg._b_subkeys.list():
            subkey = block.leader
            if seskeypkt.body.keyid == subkey.body.id:
                break # leave with the appropriate subkey
        # I know the target in question is an ElGamal key
        key_tuple = (subkey.body.ELGAMAL_p.value, subkey.body.ELGAMAL_x.value)
        cipher_tuple = (seskeypkt.body.ELGAMAL_gk_modp.value, seskeypkt.body.ELGAMAL_myk_modp.value)
        # retrieving the PKCS, etc., padded session key
        padded_message = decrypt_public(seskeypkt.body.alg_pubkey, key_tuple, cipher_tuple)
        # Rules from rfc 2437 9.1.2.2:
        # 1. Padding starts with 0x02.
        # 2. Padding continues with >= 8 octets non-zero gibberish.
        # 3. Gibberish concludes with 0x00.
        # 4. Remaining data is the message.
        if '\x02' == padded_message[0]:
            idx = padded_message.find('\x00')
            if -1 != idx and 8 <= idx:
                message = padded_message[idx+1:]
                chksum = str2int(message[-2:])
                ciphertype = str2int(message[0])
                key = message[1:len(message)-2]
                i = 0
                for e in key:
                    i += str2int(e)
                # TODO check chksum
                cleartext = decrypt_symmetric(ciphertype, key, encmsg.encrypted.body.data)
            else:
                errmsg = "Misplaced \\x00 in session key padding, located at index->(%s)" % idx
        else:
            errmsg = "Session key padding must start with \\x02, received->()" % hex(ord(padded_message[0]))
        cleartext = cleartext[10:] # ditching the prefix + 2
        # result is a compressed message..
        compressedmsg = list_msgs(list_pkts(cleartext))[0]
        newmsgs = list_msgs(list_pkts(compressedmsg.compressed.body.data))
        # ..with only one literal data packet
        literal_data = newmsgs[0].literals[0].body.data
        # compare against original file
        clrtxt = read_test_file(['pgpfiles','cleartext.txt'])
        self.assertEqual(literal_data, clrtxt)


class G00PacketLevelDecryption(unittest.TestCase):
    """Decryption Using Packets
    
    These tests check the packet-level functions..
    """
    def setUp(self):
        self.cleartext = read_test_file(['pgpfiles','cleartext.txt'])

    def testG01Decrypt1(self):
        """crypto.cipher: decrypt() v4 public (ElGamal) MDC CAST5 compressed"""
        # This message is known to have a compressed packet containing a literal
        # packet containing the text from cleartext.txt.
        enc_d = read_test_file(['pgpfiles','enc','pub.elg.cast.clrtxt.gpg'])
        key_d = read_test_file(['pgpfiles','key','DSAELG1.sec.gpg'])
        clr_d = read_test_file(['pgpfiles','cleartext.txt'])
        sespkt, encpkt = list_pkts(enc_d)
        keypkt = list_pkts(key_d)[3] # first encryption subkey (known)
        passphrase = 'test'
        msg_d = decrypt(encpkt, passphrase, sespkt, keypkt)
        compmsg = list_msgs(list_pkts(msg_d))[0]
        litpkt = list_pkts(compmsg.compressed.body.data)[0]
        self.assertEqual(clr_d, litpkt.body.data)
 
    def testG02Decrypt2(self):
        """crypto.cipher: decrypt() v4 public (ElGamal) MDC AES256 compressed"""
        # This message is known to have a compressed packet containing a literal
        # packet containing the text from cleartext.txt.
        enc_d = read_test_file(['pgpfiles','enc','pub.elg.aes256.clrtxt.gpg'])
        key_d = read_test_file(['pgpfiles','key','DSAELG1.sec.gpg'])
        clr_d = read_test_file(['pgpfiles','cleartext.txt'])
        sespkt, encpkt = list_pkts(enc_d)
        keypkt = list_pkts(key_d)[3] # first encryption subkey (known)
        passphrase = 'test'
        msg_d = decrypt(encpkt, passphrase, sespkt, keypkt)
        compmsg = list_msgs(list_pkts(msg_d))[0]
        litpkt = list_pkts(compmsg.compressed.body.data)[0]
        self.assertEqual(clr_d, litpkt.body.data)

    def testG03Decrypt3(self):
        """crypto.cipher: decrypt() v3 public (RSA nopass) 3DES compressed"""
        enc_d = read_test_file(['pgpfiles','enc','pub.pgp653rsa.clrtxt.gpg'])
        key_d = read_test_file(['pgpfiles','key','pgp653rsa.sec.nopass.gpg'])
        clr_d = read_test_file(['pgpfiles','cleartext.txt'])
        sespkt, encpkt = list_pkts(enc_d)
        passphrase = 'test'
        sespkt, encpkt = list_pkts(enc_d)
        keypkt = list_pkts(key_d)[0]
        msg_d = decrypt(encpkt, passphrase, sespkt, keypkt)
        compmsg = list_msgs(list_pkts(msg_d))[0]
        litpkt = list_pkts(compmsg.compressed.body.data)[0]
        self.assertEqual(clr_d, litpkt.body.data)

    # This was to check proper decrypting of v3 RSA secret key values.
    def testG04Decrypt4(self):
        """crypto.cipher: decrypt() v3 public (RSA) 3DES compressed"""
        prefix = ['pgpfiles','interop','pgp6.5.3','RSA1']
        enc_d = read_test_file(prefix+['encrypted.cleartext.notepad.pgp6.5.3.RSA1.pgp'])
        key_d = read_test_file(prefix+['key.pgp6.5.3.RSA1.sec.asc'])
        clr_d = read_test_file(prefix+['cleartext.notepad.txt'])
        sespkt, encpkt = list_pkts(enc_d)
        passphrase = 'test'
        # first (totally detached) armored block has [secret key pkt, uid pkt]
        arms = list_armored(key_d)
        keypkt = list_pkts(arms[0].data)[0]
        msg_d = decrypt(encpkt, passphrase, sespkt, keypkt)
        compmsg = list_msgs(list_pkts(msg_d))[0]
        litpkt = list_pkts(compmsg.compressed.body.data)[0]
        self.assertEqual(clr_d, litpkt.body.data)

    def testG05Decrypt5(self):
        """crypto.cipher: decrypt() symmetric (CAST) compressed"""
        enc_d = read_test_file(['pgpfiles','enc','sym.cast.cleartext.txt.gpg'])
        clr_d = read_test_file(['pgpfiles','cleartext.txt'])
        sespkt, encpkt = list_pkts(enc_d)
        passphrase = 'test'
        msg_d = decrypt(encpkt, passphrase, sespkt)
        compmsg = list_msgs(list_pkts(msg_d))[0]
        litpkt = list_pkts(compmsg.compressed.body.data)[0]
        self.assertEqual(clr_d, litpkt.body.data)


class H00EncryptionIntegrityProtection(unittest.TestCase):
    """
    """
    #Try following these next two tests verbatim to check against
    #encrypt_message().

    def testH01EncryptPublicElGamalDES3(self):
        """crypto.cipher: encrypt()/decrypt() ElGamal, DES3 w/ integrity"""
        key_d = read_test_file(['pgpfiles','key','DSAELG3.pub.gpg'])
        keypkt = list_pkts(key_d)[3] # ElGamal encrypting key
        msg = "My secret message."
        key = gen_random(_keysize(SYM_DES3))
        sespkt = encrypt_public_session(keypkt, key, SYM_DES3)
        encpkt = encrypt_integrity(SYM_DES3, key, msg)
        seckey_d = read_test_file(['pgpfiles','key','DSAELG3.sec.nopass.gpg'])
        seckeypkt = list_pkts(seckey_d)[2]
        clrtxt = decrypt(encpkt, None, sespkt, seckeypkt)
        self.assertEqual(msg, clrtxt)

    def testH02EncryptPublicRSAAES256(self):
        """crypto.cipher: encrypt()/decrypt() RSA, AES256 w/ integrity"""
        key_d = read_test_file(['pgpfiles','key','RSA1.pub.gpg'])
        keypkt = list_pkts(key_d)[0] # use RSA for encrypting
        alg = SYM_AES256
        msg = "My secret message."
        passphrase = 'test'
        key = gen_random(_keysize(alg))
        sespkt = encrypt_public_session(keypkt, key, alg)
        encpkt = encrypt_integrity(alg, key, msg)
        seckey_d = read_test_file(['pgpfiles','key','RSA1.sec.gpg'])
        seckeypkt = list_pkts(seckey_d)[0]
        clrtxt = decrypt(encpkt, passphrase, sespkt, seckeypkt)
        self.assertEqual(msg, clrtxt)

    def testH03EncryptSymmetric(self):
        """crypto.cipher: encrypt()/decrypt() AES256 (symmetric) w/ integrity"""
        alg = SYM_AES256
        msg = "My secret message."
        passphrase = 'test'
        sespkt = encrypt_symmetric_session(alg)
        key = string2key(sespkt.body.s2k, alg, passphrase)
        encpkt = encrypt_integrity(alg, key, msg)
        clrtxt = decrypt(encpkt, passphrase, sespkt)
        self.assertEqual(msg, clrtxt)


class I00EncryptMessagesByHand(unittest.TestCase):
    """Create actual encrypted messages by hand.
    """
    def testI01EncryptPublicElGamalDES3ZIP(self):
        """crypto.cipher: encrypt()/decrypt() ElGamal, DES3 w/ integrity, & ZIP"""
        key_d = read_test_file(['pgpfiles','key','DSAELG3.pub.gpg'])
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
        # decryption
        seckey_d = read_test_file(['pgpfiles','key','DSAELG3.sec.nopass.gpg'])
        seckeypkt = list_pkts(seckey_d)[2]
        clrtxt = decrypt(encpkt, None, sespkt, seckeypkt)
        # got compressed
        comppkt_out = list_pkts(clrtxt)[0]
        # got literal
        litpkt_out = list_pkts(comppkt_out.body.data)[0]
        self.assertEqual(d, litpkt_out.body.data)
        self.assertEqual('outfile', litpkt_out.body.filename)
        self.assertEqual(0, litpkt_out.body.modified)
        self.assertEqual('b', litpkt_out.body.format)


#class XInteropCryptPGP653PublicKeyDecryption(unittest.TestCase):
#    """PGP 6.5.3 Public Key Decryption
#
#    These tests cover messages that have been encrypted to public
#    keys.
#    """
#    def setUp(self):
#        self.cleartext = read_test_file(['pgpfiles','cleartext.txt'])
#
#    def testE01PGP(self):
#        """(interop) crypto.cipher: decrypt PGP 6.5.3 public key RSA encrypted message"""
#        msg_d = read_test_file(['pgpfiles','interop','pgp6.5.3','RSA1','encrypted.cleartext.notepad.pgp6.5.3.RSA1.pgp'])
#        msg = list_msgs(list_pkts(msg_d))[0][0]
#        print
#        print "msg: %s" % dir(msg)
#        target1 = msg.targets[0]
#        print "target1: %s" % dir(target1)
#        print "keyid: %s" % target1.body.keyid


if '__main__' == __name__:
    unittest.main()
