"""Signature Algorithm Tests
"""

import unittest
import sha
import pickle
import time
from Crypto.Util.randpool import RandomPool

# test targets
from openpgp.sap.crypto import sign_DSA
from openpgp.sap.crypto import sign_RSA
from openpgp.sap.crypto import sign_ElGamal
from openpgp.sap.crypto import sign
from openpgp.sap.crypto import verify_DSA
from openpgp.sap.crypto import verify_RSA
from openpgp.sap.crypto import verify_ElGamal
from openpgp.sap.crypto import verify

# package help
from openpgp.code import *
from openpgp.sap.list import list_pkts, list_msgs
from openpgp.sap.util.strnum import int2quadoct
from openpgp.sap.pkt.Signature import create_SignatureSubpacket

# test help
from support import read_test_file, sepjoin, curdir

txt = 'some silly message' # message to sign
k = 17 # simple k value for DSA and ElGamal sigs
# these pickles are all PyCrypto instances
dsakey = pickle.load(file(sepjoin([curdir,'pickles','dsa_key.py']), 'rb'))
rsakey = pickle.load(file(sepjoin([curdir,'pickles','rsa_key.py']), 'rb'))
elgkey = pickle.load(file(sepjoin([curdir,'pickles','elg_key.py']), 'rb'))
# one-pass signatures from GPG..
dsasig_d = read_test_file(['pgpfiles','sig','sig.DSAELG1.onepass.gpg'])
rsasig_d = read_test_file(['pgpfiles','sig','sig.RSA1.onepass.gpg'])
# ..and their corresponding public keys
dsapubkey_d = read_test_file(['pgpfiles','key','DSAELG1.pub.gpg'])
dsaseckey_d = read_test_file(['pgpfiles','key','DSAELG1.sec.gpg'])
rsapubkey_d = read_test_file(['pgpfiles','key','RSA1.pub.gpg'])


class A0PyCryptoSigTest(unittest.TestCase):
    """PyCrypto Signature Tests

    These tests just check that PyCrypto stuff works. This is a little
    redundant.
    """
    def testA01DSA_base(self):
        "PyCrypto: DSA signature/verification sanity"
        key = dsakey
        sig = key.sign(txt, k)
        ret = key.verify(txt, sig)
        self.assertEqual(ret, 1)

    def testA02RSA_base(self):
        "PyCrypto: RSA signature/verification sanity"
        key = rsakey
        sig = key.sign(txt, None)
        ret = key.verify(txt, sig)
        self.assertEqual(ret, 1)

    def testA03ELGAMAL_base(self):
        "PyCrypto: ElGamal signature/verification sanity"
        key = elgkey
        sig = key.sign(txt, k)
        ret = key.verify(txt, sig)
        self.assertEqual(ret, 1)


class B0CryptoSigTestSignVerify(unittest.TestCase):
    """Base Crypto Sign/Verify Tests

    These tests cover the base signature/verification functions for
    the implementation. By "base" I mean that the crypto functions
    are operating on the basic numbers involved with the signature
    algorithm and do not involve any hashing.
    """
    def testB01DSASignature(self):
        "crypto.signature: sign_DSA()/verify_DSA() sanity"
        sig = sign_DSA(txt, (dsakey.y, dsakey.g, dsakey.p, dsakey.q, dsakey.x))
        ret = verify_DSA(txt, sig, (dsakey.y, dsakey.g, dsakey.p, dsakey.q))
        self.assertEqual(ret, 1)
        
    def testB02RSAsignature(self):
        "crypto.signature: sign_RSA()/verify_RSA() sanity"
        sig = sign_RSA(txt, (rsakey.n, rsakey.d))
        ret = verify_RSA(txt, sig, (rsakey.n, rsakey.e))
        self.assertEqual(ret, 1)
 
    def testB03ElGamalSignature(self):
        "crypto.signature: sign_ElGamal()/verify_ElGamal() sanity"
        k = 1 # it can take a while to generate primes, this is OK for tests
        sig = sign_ElGamal(txt, (elgkey.p, elgkey.g, elgkey.x), k)
        ret = verify_ElGamal(txt, sig, (elgkey.p, elgkey.g, elgkey.y))
        self.assertEqual(ret, 1)


class C0CryptoPGPSigVerificationTest1(unittest.TestCase):
    """Hand-held Signature Verification Tests

    These tests check actual OpenPGP signatures (most likely
    generated by GnuPG) and provide the lowest level representation of
    signatures and verfication in action - making it a lot easier to
    figure out what the higher level functions should be doing.
    """
    def testC01DSAPGPSignature(self):
        "crypto.signature: verify_DSA() One-Pass v3 by hand"
        dsakey = list_pkts(dsapubkey_d)[0].body
        onepass, lit, sig = [x.body for x in list_pkts(dsasig_d)]
        # we know that this was signed using SHA1, ignoring onepass packet
        msg = sha.new(lit.data + sig.hashed_data).digest()
        sigtup = (sig.DSA_r.value, sig.DSA_s.value)
        keytup = (dsakey.DSA_y.value, dsakey.DSA_g.value, dsakey.DSA_p.value, dsakey.DSA_q.value)
        self.assertEqual(1, verify_DSA(msg, sigtup, keytup))

    def testC02RSAPGPSignature(self):
        "crypto.signature: verify_RSA() One-Pass v3 by hand"
        rsakey = list_pkts(rsapubkey_d)[0].body
        onepass, lit, sig = [x.body for x in list_pkts(rsasig_d)]
        # again, we know that this was signed using SHA1 (ignoring onepass)..
        msg = sha.new(lit.data + sig.hashed_data).digest()
        # ..and know that this is the "full hash prefix" we need:
        prefix = '\x30\x21\x30\x09\x06\x05\x2b\x0E\x03\x02\x1A\x05\x00\x04\x14'
        # by hand count (and assumption that range = length of RSA modulus):
        PS = ''
        for i in range (90):
            PS += '\xff'
        context = '\x00\x01' + PS + '\x00' + prefix + msg
        keytup = (rsakey.RSA_n.value, rsakey.RSA_e.value)
        self.assertEqual(1, verify_RSA(context, sig.RSA.value, keytup))

    def testC03ElGamalPGPSignature(self):
        "crypto.signature: verify_ElGamal() One-Pass by hand !UNTESTED!"
        pass

    def testC04DSAv4UID(self):
        "crypto.signature: verify_DSA() v4 user ID by hand"
        keypkt, uidpkt, sigpkt = list_pkts(dsapubkey_d)[:3]
        # two octet primary key length (packet body)
        keylen = int2quadoct(keypkt.length.size)[-2:]
        # four octet user ID length (packet body)
        uidlen = int2quadoct(uidpkt.length.size)
        context = sha.new('\x99'+keylen+keypkt.body._d+'\xb4'+uidlen+uidpkt.body._d+sigpkt.body.hashed_data).digest()
        sigtup = (sigpkt.body.DSA_r.value, sigpkt.body.DSA_s.value)
        keytup = (keypkt.body.DSA_y.value, keypkt.body.DSA_g.value, keypkt.body.DSA_p.value, keypkt.body.DSA_q.value)
        self.assertEqual(1, verify_DSA(context, sigtup, keytup))

    def testC05DSAv4Subkey(self):
        "crypto.signature: verify_DSA() v4 subkey by hand"
        pkts = list_pkts(dsapubkey_d)
        keypkt, subkeypkt, sigpkt = pkts[0], pkts[3], pkts[4]
        # two octet primary key length (packet body)
        keylen = int2quadoct(keypkt.length.size)[-2:]
        # two octet subkey length (packet body)
        subkeylen = int2quadoct(subkeypkt.length.size)[-2:]
        context = sha.new('\x99'+keylen+keypkt.body._d+'\x99'+subkeylen+subkeypkt.body._d+sigpkt.body.hashed_data).digest()
        sigtup = (sigpkt.body.DSA_r.value, sigpkt.body.DSA_s.value)
        keytup = (keypkt.body.DSA_y.value, keypkt.body.DSA_g.value, keypkt.body.DSA_p.value, keypkt.body.DSA_q.value)
        self.assertEqual(1, verify_DSA(context, sigtup, keytup))

    def testC06PrimaryRevocation(self):
        "crypto.signature: verify_DSA() primary key revocation by hand"
        d = read_test_file(['pgpfiles','key','DSAELG1.pub.revoked.gpg'])
        keypkt, revocpkt = list_pkts(d)[:2]
        context = sha.new(keypkt.rawstr()+revocpkt.body.hashed_data).digest()
        sigtup = (revocpkt.body.DSA_r.value, revocpkt.body.DSA_s.value)
        keytup = (keypkt.body.DSA_y.value, keypkt.body.DSA_g.value, keypkt.body.DSA_p.value, keypkt.body.DSA_q.value)
        self.assertEqual(1, verify_DSA(context, sigtup, keytup))

    def testC07SubkeyRevocation(self):
        "crypto.signature: verify_DSA() subkey revocation by hand"
        d = read_test_file(['pgpfiles','key','DSAELG2.subkeyrevoc.gpg'])
        keymsg = list_msgs(list_pkts(d))[0]
        revblock = keymsg._b_subkeys['90AFB828686B6E9A'] # known revoked block
        key = keymsg._b_primary.leader
        sig = revblock.local_bindings[0]
        subkey = revblock.leader
        l1 = int2quadoct(len(key.body._d))[-2:]
        l2 = int2quadoct(len(subkey.body._d))[-2:]
        context = sha.new('\x99'+l1+key.body._d+'\x99'+l2+subkey.body._d+sig.body.hashed_data).digest()
        sigtup = (sig.body.DSA_r.value, sig.body.DSA_s.value)
        keytup = (key.body.DSA_y.value, key.body.DSA_g.value, key.body.DSA_p.value, key.body.DSA_q.value)
        self.assertEqual(1, verify_DSA(context, sigtup, keytup))


class D0CryptoPGPSigVerificationTest2(unittest.TestCase):
    """Higher Level Signature Verification Tests

    This next set of tests use verify() to automate message
    verification. The only hand-made assumptions here are the sequence
    of packets in the given OpenPGP data. Single literal data packets
    are being used because they make it easy to get a msg' value to
    verify.
    """
    def testD01DSAPGPSig(self):
        "crypto.signature: verify() v3 DSA One-Pass"
        keypkt = list_pkts(dsapubkey_d)[0]
        msgs = list_msgs(list_pkts(dsasig_d))
        sigmsg = msgs[0]
        self.assertEqual(1, verify(sigmsg.sigs[0], sigmsg.msg, keypkt))

    def testD02RSAPGPSig(self):
        "crypto.signature: verify() v3 RSA One-Pass"
        keypkt = list_pkts(rsapubkey_d)[0]
        msgs = list_msgs(list_pkts(rsasig_d))
        sigmsg = msgs[0]
        self.assertEqual(1, verify(sigmsg.sigs[0], sigmsg.msg, keypkt))

    def testD03DSAv4UID(self):
        "crypto.signature: verify() public key user ID v4 DSA"
        msgs = list_msgs(list_pkts(dsapubkey_d))
        keymsg = msgs[0]
        uid = keymsg._b_userids[0].leader # first user id
        sig = keymsg._b_userids[0].local_bindings[0] # first applicable signature
        key = keymsg._b_primary.leader # public key
        self.assertEqual(1, verify(sig, uid, key))

    def testD03aDSAv4UIDPrivate(self):
        "crypto.signature: verify() private key user ID v4 DSA"
        msgs = list_msgs(list_pkts(dsaseckey_d))
        keymsg = msgs[0]
        uid = keymsg._b_userids[0].leader # first user id
        sig = keymsg._b_userids[0].local_bindings[0] # first applicable signature
        key = keymsg._b_primary.leader # public key
        self.assertEqual(1, verify(sig, uid, key))

    def testD04DSAv4Subkey(self):
        "crypto.signature: verify() public key subkey binding v4 DSA"
        msgs = list_msgs(list_pkts(dsapubkey_d))
        keymsg = msgs[0]
        subkey = keymsg._b_subkeys[0].leader # first subkey
        subkeysig = keymsg._b_subkeys[0].local_bindings[0] # first applicable signature
        pubkey = keymsg._b_primary.leader # public key
        self.assertEqual(1, verify(subkeysig, subkey, pubkey))

    def testD04aDSAv4SubkeyPrivate(self):
        "crypto.signature: verify() pivate key subkey binding v4 DSA"
        msgs = list_msgs(list_pkts(dsaseckey_d))
        keymsg = msgs[0]
        subkey = keymsg._b_subkeys[0].leader # first subkey
        subkeysig = keymsg._b_subkeys[0].local_bindings[0] # first applicable signature
        pubkey = keymsg._b_primary.leader # public key
        self.assertEqual(1, verify(subkeysig, subkey, pubkey))

    def testD05PrimaryRevocation(self):
        "crypto.signature: verify() primary key revocation"
        d = read_test_file(['pgpfiles','key','DSAELG1.pub.revoked.gpg'])
        keypkt, revocpkt = list_pkts(d)[:2]
        self.assertEqual(1, verify(revocpkt, keypkt, keypkt))

    def testD06SubkeyRevocation(self):
        "crypto.signature: verify() subkey revocation"
        d = read_test_file(['pgpfiles','key','DSAELG2.subkeyrevoc.gpg'])
        keymsg = list_msgs(list_pkts(d))[0]
        revblock = keymsg._b_subkeys['90AFB828686B6E9A'] # known revoked block
        key = keymsg._b_primary.leader
        sig = revblock.local_bindings[0]
        subkey = revblock.leader
        self.assertEqual(1, verify(sig, subkey, key))

    def testD07CertificationRevocation(self):
        "crypto.signature: verify() certification revocation"
        key_d = read_test_file(['pgpfiles','key','DSAELG2.revoked_uid.gpg'])
        pkts = list_pkts(key_d)
        keymsg = list_msgs(pkts)[0]
        primary_key, uid, revoker = pkts[0], pkts[3], pkts[4]
        verified = verify(revoker, uid, primary_key)
        self.assertEqual(True, verify(revoker, uid, primary_key))
    
    def testD08CertificationRevocation(self):
        "crypto.signature: verify() foreign user ID certification"
        key_d = read_test_file(['pgpfiles','key','DSAELG2.pub.foreign_uid_cert.gpg'])
        sigkey_d = read_test_file(['pgpfiles','key','RSA1.pub.gpg'])
        sigpkt = list_pkts(sigkey_d)[0]
        pkts = list_pkts(key_d)
        primary_key, uid, cert = pkts[0], pkts[1], pkts[3]
        opts = {'primary':primary_key}
        verified = verify(cert, uid, sigpkt, **opts)
        self.assertEqual(True, verified)
    

class E00SigningTests(unittest.TestCase):
    """Signing Tests
    """
    def testE01SignatureCreationV4DSABinaryNoPass(self):
        "crypto.signature: sign() v4 DSA no pass, no subpkts BINARY"
        seckey_d = read_test_file(['pgpfiles','key','DSAELG1.sec.nopass.gpg'])
        seckeypkt = list_pkts(seckey_d)[0]
        msg = 'testmessage'
        sigtype = SIG_BINARY
        sigpkt = sign(sigtype, msg, seckeypkt)
        verified = verify(sigpkt, msg, seckeypkt)
        self.assertEqual(1, verified)

    def testE02SignatureCreationV4RSATextNoPass(self):
        "crypto.signature: sign() v4 RSA no pass, no subpkts TEXT"
        seckey_d = read_test_file(['pgpfiles','key','DSAELG1.sec.nopass.gpg'])
        seckeypkt = list_pkts(seckey_d)[0]
        msg = 'testmessage\r\nyaddaboo\n\nsdfll\r\n'
        sigtype = SIG_TEXT
        sigpkt = sign(sigtype, msg, seckeypkt)
        verified = verify(sigpkt, msg, seckeypkt)
        self.assertEqual(1, verified)

    def testE03SignatureCreationV4DSAText(self):
        "crypto.signature: sign() v4 DSA no subpkts TEXT"
        seckey_d = read_test_file(['pgpfiles','key','DSAELG1.sec.gpg'])
        seckeypkt = list_pkts(seckey_d)[0]
        msg = 'testmessage\r\nyaddaboo\n\nsdfll\r\n'
        sigtype = SIG_TEXT
        sigpkt = sign(sigtype, msg, seckeypkt, passphrase="test")
        verified = verify(sigpkt, msg, seckeypkt)
        self.assertEqual(1, verified)

    def testE04SignatureCreationV4RSAText(self):
        "crypto.signature: sign() v4 RSA no subpkts TEXT"
        seckey_d = read_test_file(['pgpfiles','key','RSA1.sec.gpg'])
        seckeypkt = list_pkts(seckey_d)[0]
        msg = 'testmessage\r\nyaddaboo\n\nsdfll\r\n'
        sigtype = SIG_TEXT
        sigpkt = sign(sigtype, msg, seckeypkt, passphrase="test")
        verified = verify(sigpkt, msg, seckeypkt)
        self.assertEqual(1, verified)

    def testE05SignatureCreationV4DSATextSubpackets(self):
        "crypto.signature: sign() v4 DSA with hashed subpkts TEXT"
        seckey_d = read_test_file(['pgpfiles','key','DSAELG1.sec.gpg'])
        seckeypkt = list_pkts(seckey_d)[0]
        msg = 'testmessage\r\nyaddaboo\n\nsdfll\r\n'
        sigtype = SIG_TEXT
        created = int(time.time()) - 5000
        subpkt_created = create_SignatureSubpacket(SIGSUB_CREATED, created)
        subpkt_keyid = create_SignatureSubpacket(SIGSUB_SIGNERID, seckeypkt.body.id)
        opts = {'passphrase':'test', 'hashed_subpkts':[subpkt_created],
                'unhashed_subpkts':[subpkt_keyid]}
        sigpkt = sign(sigtype, msg, seckeypkt, **opts)
        verified = verify(sigpkt, msg, seckeypkt)
        self.assertEqual(1, verified)

    def testE06SignatureCreationV4RSABinarySubpackets(self):
        "crypto.signature: sign() v4 RSA with hashed subpkts BINARY"
        seckey_d = read_test_file(['pgpfiles','key','RSA1.sec.gpg'])
        seckeypkt = list_pkts(seckey_d)[0]
        msg = 'testmessage\r\nyaddaboo\n\nsdfll\r\n'
        sigtype = SIG_BINARY
        created = int(time.time()) - 5000
        subpkt_created = create_SignatureSubpacket(SIGSUB_CREATED, created)
        subpkt_keyid = create_SignatureSubpacket(SIGSUB_SIGNERID, seckeypkt.body.id)
        opts = {'passphrase':'test', 'hashed_subpkts':[subpkt_created],
                'unhashed_subpkts':[subpkt_keyid]}
        sigpkt = sign(sigtype, msg, seckeypkt, **opts)
        verified = verify(sigpkt, msg, seckeypkt)
        self.assertEqual(1, verified)

    def testE07SignatureCreationV3DSABinarySubpackets(self):
        "crypto.signature: sign() v3 DSA with hashed subpkts BINARY"
        import time
        seckey_d = read_test_file(['pgpfiles','key','DSAELG1.sec.gpg'])
        seckeypkt = list_pkts(seckey_d)[0]
        msg = 'testmessage\r\nyaddaboo\n\nsdfll\r\n'
        sigtype = SIG_BINARY
        created = int(time.time()) - 5000
        opts = {'passphrase':'test', 'version':3, 'created':created,
                'keyid':seckeypkt.body.id}
        sigpkt = sign(sigtype, msg, seckeypkt, **opts)
        verified = verify(sigpkt, msg, seckeypkt)
        self.assertEqual(1, verified)

    def testE08SignatureCreationV3RSATextSubpackets(self):
        "crypto.signature: sign() v3 RSA with hashed subpkts TEXT"
        import time
        seckey_d = read_test_file(['pgpfiles','key','RSA1.sec.gpg'])
        seckeypkt = list_pkts(seckey_d)[0]
        msg = 'testmessage\r\nyaddaboo\n\nsdfll\r\n'
        sigtype = SIG_TEXT
        created = int(time.time()) - 5000
        opts = {'passphrase':'test', 'version':3, 'created':created,
                'keyid':seckeypkt.body.id}
        sigpkt = sign(sigtype, msg, seckeypkt, **opts)
        verified = verify(sigpkt, msg, seckeypkt)
        self.assertEqual(1, verified)


class F00DirectSignatures(unittest.TestCase):
    """Direct sigs
    
    In verify(), the parameters refer to:
        1. sigpkt
        2. the key the direct sig is on
        3. the key that made the direct sig
    """
    def testF01DSADirectPrimary(self):
        "crypto.signature: sign() v4 DSA direct (self signature on primary)"
        seckey_d = read_test_file(['pgpfiles','key','DSAELG1.sec.gpg'])
        seckeypkt = list_pkts(seckey_d)[0]
        sigtype = SIG_DIRECT
        sigpkt = sign(sigtype, seckeypkt, seckeypkt, passphrase="test")
        verified = verify(sigpkt,  seckeypkt, seckeypkt)
        self.assertEqual(1, verified)

    def testF02DSADirectSubkey(self):
        "crypto.signature: sign() v4 DSA direct (self signature on subkey)"
        seckey_d = read_test_file(['pgpfiles','key','DSAELG1.sec.gpg'])
        pkts = list_pkts(seckey_d)
        seckeypkt, subkeypkt = pkts[0], pkts[3]
        sigtype = SIG_DIRECT
        opts = {'passphrase':'test', 'primary':seckeypkt}
        sigpkt = sign(sigtype, subkeypkt, seckeypkt, **opts)
        verified = verify(sigpkt, subkeypkt, seckeypkt)
        self.assertEqual(1, verified)

    def testF03DSADirectForeign(self):
        "crypto.signature: sign() v4 DSA direct on foreign primary key"
        targetkey_d = read_test_file(['pgpfiles','key','DSAELG3.pub.gpg'])
        seckey_d = read_test_file(['pgpfiles','key','DSAELG1.sec.gpg'])
        targetkeypkt = list_pkts(targetkey_d)[0]
        seckeypkt = list_pkts(seckey_d)[0]
        sigtype = SIG_DIRECT
        opts = {'passphrase':'test', 'primary':targetkeypkt}
        sigpkt = sign(sigtype, targetkeypkt, seckeypkt, **opts)
        verified = verify(sigpkt, targetkeypkt, seckeypkt,
                              primary=targetkeypkt)
        self.assertEqual(1, verified)

    def testF04DSADirectForeignSuby(self):
        "crypto.signature: sign() v4 DSA direct on foreign subkey"
        targetkey_d = read_test_file(['pgpfiles','key','DSAELG3.pub.gpg'])
        seckey_d = read_test_file(['pgpfiles','key','DSAELG1.sec.gpg'])
        targetpkts = list_pkts(targetkey_d)
        targetprimarypkt, targetkeypkt = targetpkts[0], targetpkts[3]
        seckeypkt = list_pkts(seckey_d)[0]
        sigtype = SIG_DIRECT
        opts = {'passphrase':'test', 'primary':targetprimarypkt}
        sigpkt = sign(sigtype, targetkeypkt, seckeypkt, **opts)
        verified = verify(sigpkt, targetkeypkt, seckeypkt,
                              primary=targetprimarypkt)
        self.assertEqual(1, verified)


class G00CertRevocationSignatures(unittest.TestCase):
    """
    """
    def testG01CreateUIDRevocation(self):
        "crypto.signature: sign() local certification revocation (0x30)"
        key_d = read_test_file(['pgpfiles','key','DSAELG1.sec.gpg'])
        pkts = list_pkts(key_d)
        seckey, uid = pkts[0], pkts[1]
        sigtype = SIG_CERTREVOC
        opts = {'passphrase':'test', 'primary':seckey}
        sigpkt = sign(sigtype, uid, seckey, **opts)
        verified = verify(sigpkt, uid, seckey)
        self.assertEqual(True, verified)


# these next two functions and the make_keys() call below
# were used to make the pickled keys in the tests above.
#def report(s):
#    print "doing something interesting with: %s" % s
#
#def make_keys():
#    """Make and pickle a bunch of keys in ./pickles/.
#    """
#    import Crypto.PublicKey.DSA as DSA
#    import Crypto.PublicKey.RSA as RSA
#    import Crypto.PublicKey.ElGamal as ELG
#
#    keysize = 1024
#    rnd = RandomPool()
#    rnd.stir()
#    dsa_key = DSA.generate(keysize, rnd.get_bytes, report)
#    dsa_file = file('pickles'+os.sep+'dsa_key.py', 'w')
#    pickle.dump(dsa_key, dsa_file)
#    rnd.stir()
#    rsa_key = RSA.generate(keysize, rnd.get_bytes, report)
#    rsa_file = file('pickles'+os.sep+'rsa_key.py', 'w')
#    pickle.dump(rsa_key, rsa_file)
#    rnd.stir()
#    elg_key = ELG.generate(keysize, rnd.get_bytes, report)
#    elg_file = file('pickles'+os.sep+'elg_key.py', 'w')
#    pickle.dump(elg_key, elg_file)
#
#make_keys()

if '__main__' == __name__:
    unittest.main()