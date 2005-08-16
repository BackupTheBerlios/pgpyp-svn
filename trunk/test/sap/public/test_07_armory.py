"ASCII-Armor Tests"

import os
import unittest

# test targets
from openpgp.sap.armory import list_armored
from openpgp.sap.armory import apply_armor

# package help
from openpgp.code import *
from openpgp.sap.exceptions import *
from openpgp.sap.list import list_pkts, list_msgs

# test help
from support import read_test_file

# Creating test cases - thought I should mention how these were pieced
# together.. the tests basically challenge the ability for Armory
# functions to make sense of ASCII-Armored headers (..BEGIN PGP..)
# and reconcile the armored data with a chksum.
# 
# 1. Bogus PGP data is arbitrarily set -> data = 'abcdefg'
# 2. Data chksum is computed -> datachksum = crc24(data)
# 3. The data is encoded in base64 -> data64 = base64.encodestring(data)
# 4. The chksum is converted to binary (string) data -> 
#        chksumstr = binascii.unhexlify(hex(datachksum)[2:])
# 5. The chksum string is encoded in base64 ->
#        chksum64 = base64.encodestring(chksumstr)
# Example:
# data = "One of these lives has a future, the other does not."
# datachksum = 8725147
# data64 = 'T25lIG9mIHRoZXNlIGxpdmVzIGhhcyBhIGZ1dHVyZSwgdGhlIG90aGVyIGRvZXMgbm90Lg==\n'
# chksumstr = '\x85"\x9b'
# chksum64 = 'hSKb\n'

################################################ good (dummy) cases
# note that this also tests the detection of the 4 basic armored types:
# -----BEGIN PGP MESSAGE-----
# -----BEGIN PGP PUBLIC KEY BLOCK-----
# -----BEGIN PGP PRIVATE KEY BLOCK-----
# -----BEGIN PGP SIGNATURE-----
# but the data contained is obviously invalid, testing only the ability
# to confirm the chksum
goodasc = [{'data':"One of these lives has a future, the other does not.",
'armored':"""
-----BEGIN PGP MESSAGE-----
Header: Value

T25lIG9mIHRoZXNlIGxpdmVzIGhhcyBhIGZ1dHVyZSwgdGhlIG90aGVyIGRvZXMg
bm90Lg==
=hSKb
-----END PGP MESSAGE-----
"""}, {'data':"You are part of the rebel alliance and a traitor.",
'armored':"""
-----BEGIN PGP PUBLIC KEY BLOCK-----
Header: Value

WW91IGFyZSBwYXJ0IG9mIHRoZSByZWJlbCBhbGxpYW5jZSBhbmQgYSB0cmFpdG9y
Lg==
=XcGP
-----END PGP PUBLIC KEY BLOCK-----
"""},
{'data':"The mouse? He left our house.",
'armored':"""
-----BEGIN PGP PRIVATE KEY BLOCK-----
Header: Value

VGhlIG1vdXNlPyBIZSBsZWZ0IG91ciBob3VzZS4=
=V9f+
-----END PGP PRIVATE KEY BLOCK-----
"""},
{'data':"Proudfeet!",
'armored':"""
-----BEGIN PGP SIGNATURE-----
Header: Value

UHJvdWRmZWV0IQ==
=7yiD
-----END PGP SIGNATURE-----
"""}]

################################### good dummy case w/ multiple messages
# 'data' list corresponds to order in which the armored messages appear
# all data is bogus PGP, set only to test data ~ chksum
multasc = {'data':["The mouse? He left our house.","Proudfeet!"],
'armored':"""
Some text preceding interesting stuff..

-----BEGIN PGP PRIVATE KEY BLOCK-----
Header: Value

VGhlIG1vdXNlPyBIZSBsZWZ0IG91ciBob3VzZS4=
=V9f+
-----END PGP PRIVATE KEY BLOCK-----

Text in between the interesting stuff..

-----BEGIN PGP SIGNATURE-----
Header: Value

UHJvdWRmZWV0IQ==
=7yiD
-----END PGP SIGNATURE-----
Text following interesting stuff..
"""}

################################################# signature
# copied dummy signature from above
sigasc = {'msgdata':"""The first line of the signed message.
The second line of the signed message.



Fifth.


""",
'sigdata':"Proudfeet!",
'armored':"""
-----BEGIN PGP SIGNED MESSAGE-----
Header: Value

The first line of the signed message.
The second line of the signed message.



Fifth.


-----BEGIN PGP SIGNATURE-----
Header: Value

UHJvdWRmZWV0IQ==
=7yiD
-----END PGP SIGNATURE-----
"""}

################################################ bad chksum cases
# copied cases 1&2 from goodasc list above
badchksum = [#changed first character in data body (T->U)
"""
-----BEGIN PGP MESSAGE-----
Header: Value

U25lIG9mIHRoZXNlIGxpdmVzIGhhcyBhIGZ1dHVyZSwgdGhlIG90aGVyIGRvZXMg
bm90Lg==
=hSKb
-----END PGP MESSAGE-----
""",#changed second character in chksum (c->d)
"""
-----BEGIN PGP PUBLIC KEY BLOCK-----
Header: Value

WW91IGFyZSBwYXJ0IG9mIHRoZSByZWJlbCBhbGxpYW5jZSBhbmQgYSB0cmFpdG9y
Lg==
=XdGP
-----END PGP PUBLIC KEY BLOCK-----
"""]

gpgpubkey = """
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1.2.2 (GNU/Linux)

mQGiBD8HGPsRBACaB0QJX+RLd1ATWlEcqQGcv1vax8YkitT9kIqN9iLPOx7n/Zw4
g8kwFvk1OlOIAZm0eoF3GJ7yTsXvYKRtZVJBkyeVUMsb/GYqGVt1a1C5d8GBScIL
mnHphFhs25COnnnubbdKvZYx35SgC4/u2okIJTFQdQGtIIcwWSp4kh/VTwCgiWRk
Unn6RVFDeYsh8ik7Jt/CZ2cD/RdpVtbTG4nM0YSwKNXOBFeRp60KkK0tmlMFJAl0
rsIcGfonpMbLJ9f7YYHqPaiwPEslU1QhaLtRuGYKUyQtYXREdipBswfsSYQ7gU0Q
HZlAk2z2TUqjq8vX65jjNvgdkVGzR06/omZeNhZl1w4Q1k6TKOnUJmpiVNuA8yXs
7vyhA/9TT9nxuNDMtzvPWWI+6Qcn8W23cLUcv3L4MpffHXd1nPrkSNJvVay/fm5D
I4PlddbiOrA4dJU+MpilOTOV0bCDtPHJ+j1ZTaCBnlHqTzitdRrwX1lJWL2o41R5
dQwnAxPalsab9zBdt2gnfUNoDosJBOj2ZxxRL3FJJYh2Vv9ddbQmVGVzdGVyIChU
ZXN0IENvbW1lbnQpIDx0ZXN0QHRlc3QudGVzdD6IWwQTEQIAGwUCPwcY+wYLCQgH
AwIDFQIDAxYCAQIeAQIXgAAKCRAM/CttzAed82zWAJ90I0xw0zuixqxX+9/lyF7s
OT1bRgCfVWBZiM0dnqe9EeUVVjo4NSCC+HO5AQ0EPwcY/RAEAKjyFZCXpZhH4vtv
fqU2ATFPY8flgn7TH/3tq3n6/NIEqDR5Qo5HKYEwqC49ZI8Vvk+gzvCaqjgzH26A
1yJWfIfj6E7yoASrAEf/x1r7yJch07sz7szIWodZswG3c+KQhxXJUttYFgiA91x8
3IZAGGzeZJ+fUt5m1PTI8AX4sSvrAAMGA/0e2ieeCIyWIIkgVqUwqd4VZ9IpB+Xg
dHPRLa5pFA3YLyHYz367uTDhv82emxpupILOhAqRIda+LxwG/5LVR9oPfRO1vrlk
u0xAsoj2jdcHSIgtSOAB7ItqttKZxvIQkbUmJOes+9B4j5aouFL/WCHiwVVbK0EE
5bAvwUSRMsROBohGBBgRAgAGBQI/Bxj9AAoJEAz8K23MB53z6qcAnAtUsHsWXk2O
ysPa9aSv/v0PRefvAJ4nooeD8J4wvpzcyY50Roc1lgeYkQ==
=Eshk
-----END PGP PUBLIC KEY BLOCK-----
"""

class A0BasicArmoredTests(unittest.TestCase):
    """Basic Armor-decoding Tests

    These tests check armor functionality on the highest level:
    checksum tests, detecting multiple armored messages, and
    clearsigned message parsing. These tests do not reconcile
    anything on the OpenPGP level (ex. sigs and public key data
    are just dummy strings).
    """
    def testA1ChksumFailure(self):
        "armory: catch bad chksums (Armory.ChksumError)"
        for ascmsg in badchksum:
            self.assertRaises(PGPFormatError, list_armored, ascmsg)

    def testA2SingleMessages(self):
        "armory: detect ASCII-armored messages, confirm body data~chksum"
        for ascmsg in goodasc:
            msg = list_armored(ascmsg['armored'])[0]
            self.assertEqual(msg.data, ascmsg['data'])
 
    # check that each armored message in the string returns the proper
    # data in order
    def testA3MultipleMessages(self):
        "armory: detect multiple ASCII-armored messages, confirm data~chksum"
        msgs = list_armored(multasc['armored'])
        for i in range(len(msgs)):
            self.assertEqual(multasc['data'][i], msgs[i].data)

    # msg 1 should be the signed data (PGP SIGNED MESSAGE), 
    # msg 2 should be the signature data (PGP SIGNATURE)
    def testA4Clearsign(self):
        "armory: detect clearsigned block, confirm data~chksum of signature"
        msgs = list_armored(sigasc['armored'])
        self.assertEqual(sigasc['msgdata'], msgs[0].signed) # signed message data
        self.assertEqual(sigasc['sigdata'], msgs[0].data) # signature data

class B0ArmoredKeyTests(unittest.TestCase):
    """Armored Key Message Tests

    These tests check list_armored()'s ability to properly return
    public key-based data.
    """
    def testB1gpgpubkey(self):
        "armory: retrieve armored public key message (GnuPG 1.2.2)"
        apkey = list_armored(gpgpubkey)[0]
        msgs = list_msgs(list_pkts(apkey.data))
        self.assertEqual(MSG_PUBLICKEY, msgs[0].type)

class C00ArmoredCreation(unittest.TestCase):
    """
    """
    def testC01CreateArmoredPublicKey(self):
        "armory: apply_armor() DSA/ElGamal public key"
        gpg_d = read_test_file(['pgpfiles','key','DSAELG1.pub.gpg'])
        msg = list_msgs(list_pkts(gpg_d))[0]
        armored_d = apply_armor(msg)
        armored = list_armored(armored_d)[0]
        newmsg = list_msgs(list_pkts(armored.data))[0]
        self.assertEqual('PUBLIC KEY BLOCK', armored.title)
        self.assertEqual(msg.rawstr(), newmsg.rawstr())

    def testC02CreateArmoredEncrypted(self):
        "armory: apply_armor() ElGamal/CAST encrypted message"
        gpg_d = read_test_file(['pgpfiles','enc','pub.elg.aes256.clrtxt.gpg'])
        msg = list_msgs(list_pkts(gpg_d))[0]
        armored_d = apply_armor(msg)
        #f = file('pgpfiles/enc/sap.pub.elg.aes256.clrtxt.asc', 'w')
        #f.write(armored_d)
        #f.close()
        armored = list_armored(armored_d)[0]
        newmsg = list_msgs(list_pkts(armored.data))[0]
        self.assertEqual('MESSAGE', armored.title)
        self.assertEqual(msg.rawstr(), newmsg.rawstr())

    def testC03CreateArmoredCompressedSigned(self):
        "armory: apply_armor() signed, compressed message"
        gpg_d = read_test_file(['pgpfiles','sig','sig.DSAELG1.comp.gpg'])
        msg = list_msgs(list_pkts(gpg_d))[0]
        armored_d = apply_armor(msg)
        armored = list_armored(armored_d)[0]
        newmsg = list_msgs(list_pkts(armored.data))[0]
        self.assertEqual('MESSAGE', armored.title)
        self.assertEqual(msg.rawstr(), newmsg.rawstr())

    # As a matter of course, SIGNED MESSAGEs don't seem to be reported as such
    # unless they're clearsigned.
    def testC04CreateArmoredSigned(self):
        "armory: apply_armor() signed, uncompressed message"
        gpg_d = read_test_file(['pgpfiles','sig','sig.DSAELG1.onepass.gpg'])
        msg = list_msgs(list_pkts(gpg_d))[0]
        armored_d = apply_armor(msg)
        armored = list_armored(armored_d)[0]
        newmsg = list_msgs(list_pkts(armored.data))[0]
        self.assertEqual('MESSAGE', armored.title)
        self.assertEqual(msg.rawstr(), newmsg.rawstr())

    def __testC05CreateArmoredClearSigned(self):
        "armory: apply_armor() clearsigned message"
        gpg_d = read_test_file(['pgpfiles','sig','sig.DSAELG1.onepass.gpg'])
        msg = list_msgs(list_pkts(gpg_d))[0]
        armored_d = apply_armor(msg, clearsign=True)
        armored = list_armored(armored_d)[0]
        newmsg = list_msgs(list_pkts(armored.data))[0]
        self.assertEqual('SIGNED MESSAGE', armored.title)
        self.assertEqual(msg.rawstr(), newmsg.rawstr())

    def __testC06(self):
        "armory: clearsigned -> native"
        import OpenPGP.sap.sap as SAP
        gpg_d = read_test_file(['pgpfiles','sig','sig.DSAELG1.clear.asc'])
        #msgs = SAP.dearmor(gpg_d)
        #print msgs

if '__main__' == __name__:
    unittest.main()
