"""Message Organization Tests

These tests just make sure that a list of packet instances which form an
OpenPGP message according to rfc2440 10.2 are recognized as such.

Tests here should focus on organizing messages, not on the particular details
of each type of message (attributes and methods).

Because list_msgs(), etc. only cares about the packet *type* and because I was
too lazy to use bona-fide valid packets, the packet instances created in these
tests are empty shells from 'empty_packets.py' that contain only enough
information to get the job done.

These packet shells are assembled by hand into test patterns, and run through
list_msgs(), etc., whose return values are checked for correctness.
"""

import unittest
import os
import copy

# test targets
from openpgp.sap.list import list_pkts, list_msgs

# package help
from openpgp.code import *

# test help
import empty_packets as EMPTY
from support import read_test_file


dsapubkey_d = read_test_file(['pgpfiles','key','DSAELG1.pub.gpg'])
# different packet combinations that comply with OpenPGP grammar
# listed as (type, [packet_list]) tuples
# all of the packet lists should contain only one complete OpenPGP message
single_empty_literal_msgs    = [(MSG_LITERAL,    [EMPTY.litdat])]
single_empty_compressed_msgs = [(MSG_COMPRESSED, [EMPTY.cmpr])]
single_empty_encrypted_msgs  = [(MSG_ENCRYPTED,  [EMPTY.symencint]),
                                (MSG_ENCRYPTED,  [EMPTY.pubseskey, 
                                                  EMPTY.symencint]),
                                (MSG_ENCRYPTED,  [EMPTY.pubseskey, 
                                                  EMPTY.pubseskey, 
                                                  EMPTY.pubseskey, 
                                                  EMPTY.symencint])]
single_empty_signed_msgs     = [(MSG_SIGNED,     [EMPTY.sig,
                                                  EMPTY.cmpr]),
                                (MSG_SIGNED,     [EMPTY.onepass,
                                                  EMPTY.pubseskey, 
                                                  EMPTY.pubseskey, 
                                                  EMPTY.pubseskey, 
                                                  EMPTY.symencint,
                                                  EMPTY.sig])]

signest_onepass = [(MSG_SIGNED, [EMPTY.onepass, 
                                 EMPTY.onepass,
                                 EMPTY.onepass,
                                 EMPTY.onepass,
                                 EMPTY.pubseskey, #
                                 EMPTY.pubseskey, # message
                                 EMPTY.pubseskey, # content
                                 EMPTY.symencint, #
                                 EMPTY.sig,
                                 EMPTY.sig,
                                 EMPTY.sig,
                                 EMPTY.sig])]

signest_normal = [(MSG_SIGNED, [EMPTY.sig,
                                EMPTY.sig,
                                EMPTY.sig,
                                EMPTY.sig,
                                EMPTY.sig,
                                EMPTY.pubseskey,   #
                                EMPTY.pubseskey,   # message
                                EMPTY.pubseskey,   # content
                                EMPTY.symencint])] # 


class B00ListMessagesTests(unittest.TestCase):
    """Organize OpenPGP messages with list_msgs()

    list_msgs() organizes OpenPGP packet lists into message
    instances instead of leaving them as individual packet lists.
    Here, packet lists are run through list_msgs() and turned
    into lists of messages and packet leftovers.
 
    Correct message instance and leftover packet instance 'type'
    attributes are checked to confirm that message listing is done
    right.
    """

    def setUp(self):
        # since there's a bunch of list manipulation in the tests
        self.single_empty_literal_msgs    = copy.deepcopy(single_empty_literal_msgs)
        self.single_empty_compressed_msgs = copy.deepcopy(single_empty_compressed_msgs)
        self.single_empty_encrypted_msgs  = copy.deepcopy(single_empty_encrypted_msgs)
        self.single_empty_signed_msgs     = copy.deepcopy(single_empty_signed_msgs)
        self.signest_onepass              = copy.deepcopy(signest_onepass)
        self.signest_normal               = copy.deepcopy(signest_normal)

    # simple message organization
    def testB01ListLiteral(self):
        """message.list_msgs: single literal message"""
        for msg in self.single_empty_literal_msgs:
            msgs = list_msgs(msg[1])
            self.assertEqual(msg[0], msgs[0].type)

    def testB02ListCompressed(self):
        """message.list_msgs: single compressed message"""
        for msg in self.single_empty_compressed_msgs:
            msgs = list_msgs(msg[1])
            self.assertEqual(msg[0], msgs[0].type)

    def testB03ListEncrypted(self):
        """message.list_msgs: single encrypted message"""
        for msg in self.single_empty_encrypted_msgs:
            msgs = list_msgs(msg[1])
            self.assertEqual(msg[0], msgs[0].type)
    
    def testB04ListSigned(self):
        """message.list_msgs: single signed message"""
        for msg in self.single_empty_signed_msgs:
            msgs = list_msgs(msg[1])
            self.assertEqual(msg[0], msgs[0].type)
    
    def testBO5ListPublicKey(self):
        """message.list_msgs: public key message"""
        pkts = list_pkts(dsapubkey_d)
        msgs = list_msgs(pkts)
        self.assertEqual(MSG_PUBLICKEY, msgs[0].type)

    def testB06ListLeftovers(self):
        """message.list_msgs: find packet leftovers"""
        for msgtype in [self.single_empty_literal_msgs, 
                        self.single_empty_compressed_msgs, 
                        self.single_empty_encrypted_msgs,
                        self.single_empty_signed_msgs]:
            for msg in msgtype:
                msg[1].append(EMPTY.uid)
                msg[1].append(EMPTY.uid)
                l = []
                msgs = list_msgs(msg[1], leftover=l)
                self.assertEqual(msg[0], msgs[0].type)
                self.assertEqual(l[0].tag.type, EMPTY.uid.tag.type)
                self.assertEqual(l[1].tag.type, EMPTY.uid.tag.type)
                self.assertEqual(len(l), 2)

    def testB07ListMultiple_1(self):
        """message.list_msgs: multiple messages, nothing leftover""" 
        enc_msg = self.single_empty_encrypted_msgs[2]
        sig_msg = self.single_empty_signed_msgs[1]
        l = []
        msgs = list_msgs(enc_msg[1] + sig_msg[1], leftover=l) 
        self.assertEqual(msgs[0].type, enc_msg[0])
        self.assertEqual(msgs[1].type, sig_msg[0])
        self.assertEqual(len(l), 0) # nothing leftover

    def testB08NestedOnePassSigs(self):
        """message.list_msgs: nested one-pass signatures""" 
        sig_msgs = self.signest_onepass
        for sig_msg in sig_msgs:
            msgs = list_msgs(sig_msg[1])
            self.assertEqual(sig_msg[0], msgs[0].type)

    def testB09NestedOnePassSigsLeftovers(self):
        """message.list_msgs: nested one-pass signatures with leftovers""" 
        sig_msgs = self.signest_onepass
        for sig_msg in sig_msgs:
            sig_msg[1].append(EMPTY.sig) # add lone signature packet
            l = []
            msgs = list_msgs(sig_msg[1], leftover=l)
            # we have 4 nested onepass sigs
            mainsig = msgs[0]
            self.assertEqual(mainsig.msg.type, MSG_SIGNED)
            self.assertEqual(mainsig.msg.msg.type, MSG_SIGNED)
            self.assertEqual(mainsig.msg.msg.msg.type, MSG_SIGNED)
            self.assertEqual(mainsig.msg.msg.msg.msg.type, MSG_ENCRYPTED)
            self.assertEqual(sig_msg[0], mainsig.type)
            # identify lone signature packet as a leftover
            #self.assertEqual(msgs[1][0].tag.type, EMPTY.sig.tag.type)
            self.assertEqual(l[0].tag.type, EMPTY.sig.tag.type)

    def testB10NestedNormalSigs(self):
        """message.list_msgs: nested normal signatures""" 
        sig_msgs = self.signest_normal
        for sig_msg in sig_msgs:
            msgs = list_msgs(sig_msg[1])
            self.assertEqual(sig_msg[0], msgs[0].type)

    def testB11NestedNormalSigsLeftovers(self):
        """message.list_msgs: nested normal signatures with leftovers""" 
        sig_msgs = self.signest_normal
        for sig_msg in sig_msgs:
            sig_msg[1].append(EMPTY.sig) # add lone signature packet
            msgs = list_msgs(sig_msg[1])
            self.assertEqual(sig_msg[0], msgs[0].type)


class EncryptedMsgTest(unittest.TestCase):
    """Encrypted Message Parsing Tests

    These tests just make sure that known values are being represented.
    """
    # symmetrically encrypted message
    def testA01SymmetricSingleTargetCAST5(self):
        """message.EncryptedMsg: single symmetric target EncryptedMsg"""
        msg_d = read_test_file(['pgpfiles','enc','sym.cast.cleartext.txt.gpg'])
        msgs = list_msgs(list_pkts(msg_d))
        encmsg = msgs[0]
        self.assertEqual(MSG_ENCRYPTED, encmsg.type)
        self.assertEqual(0, encmsg.integrity)
        self.assertEqual(1, len(encmsg.targets))
        self.assertEqual(3, encmsg.targets[0].tag.type)
        self.assertEqual(59, len(encmsg.encrypted.body.data))
    # integrity protected message
    def testA02ProtectedSingleTargetCAST5(self):
        """message.EncryptedMsg: single symmetric target protected (MDC) EncryptedMsg"""
        msg_d = read_test_file(['pgpfiles','enc','mdc.14.212.136.clrtxt.gpg'])
        msgs = list_msgs(list_pkts(msg_d))
        encmsg = msgs[0]
        self.assertEqual(MSG_ENCRYPTED, encmsg.type)
        self.assertEqual(1, encmsg.integrity)
        self.assertEqual(1, len(encmsg.targets))
        self.assertEqual(3, encmsg.targets[0].tag.type)
        self.assertEqual(80, len(encmsg.encrypted.body.data))
    # public key encrypted message
    def testA03PublicKeyEncryptedMsg(self):
        """message.EncryptedMsg: single public key target EncryptedMsg""" 
        msg_d = read_test_file(['pgpfiles','enc','pub.elg.aes256.clrtxt.gpg'])
        msgs = list_msgs(list_pkts(msg_d))
        encmsg = msgs[0]
        self.assertEqual(MSG_ENCRYPTED, encmsg.type)
        self.assertEqual(1, encmsg.integrity)
        self.assertEqual(1, len(encmsg.targets))
        self.assertEqual(1, encmsg.targets[0].tag.type)
        self.assertEqual(95, len(encmsg.encrypted.body.data))


class InteropPGP653EncryptedMsg(unittest.TestCase):
    """PGP 6.5.3 Encrypted Message Tests
    """
    def testA01PublicKeyEncryptedMsg(self):
        """(interop) message.EncryptedMsg: PGP 6.5.3 single public key target EncryptedMsg"""
        msg_d = read_test_file(['pgpfiles','interop','pgp6.5.3','RSA1','encrypted.cleartext.notepad.pgp6.5.3.RSA1.pgp'])
        msgs = list_msgs(list_pkts(msg_d))
        encmsg = msgs[0]
        self.assertEqual(MSG_ENCRYPTED, encmsg.type)
        self.assertEqual(0, encmsg.integrity)
        self.assertEqual(1, len(encmsg.targets))
        self.assertEqual(1, encmsg.targets[0].tag.type)
        self.assertEqual(85, len(encmsg.encrypted.body.data))


class A00PublicKeyMsgTest(unittest.TestCase):
    # This is a sequence test checking that packet order is preserved.
    # This is not supposed to be a guarantee that order is preserved for
    # userids and attributes (which are no problem in this particular case),
    # just a test for subkeys.
    def testA01PublicKeyAttributes(self):
        "PublicKeyMsg: attribute order check"
        key_d = read_test_file(['pgpfiles','key','DSAELG2.subkeyrevoc.gpg'])
        pkts = list_pkts(key_d) # for sequence test
        keymsg = list_msgs(pkts)[0]
        # check type
        self.assertEqual(keymsg.type, MSG_PUBLICKEY)
        # user ids
        self.assertEqual(keymsg._b_userids[0].leader.body.value,
                         'test2 (test many subkeys) <test2@test2.test2>')
        self.assertEqual(keymsg._b_userids[0], 
                         keymsg._b_userids['test2 (test many subkeys) <test2@test2.test2>'])
        # account for all the subkey IDs, *ordering is important*
        known_subkey_ids = ['1BEA996EB8246578',
                            'A4E57E4D8A3BAAE8',
                            'B45D57C94A595CEE',
                            '90AFB828686B6E9A',
                            '52E7E945372C2D26',
                            'A6EA514C4F7232B2']
        self.assertEqual(known_subkey_ids, keymsg._b_subkeys.keylist)
        # check that block list matches up with dictionary values
        for i  in  enumerate(keymsg._b_subkeys.keylist):
            self.assertEqual(keymsg._b_subkeys[i[0]],
                             keymsg._b_subkeys[i[1]])
        # check that primary key is represented
        self.assertEqual('6246EF319AC13CFC', keymsg.primary_id)
        self.assertEqual('6246EF319AC13CFC', keymsg._b_primary.leader.body.id)
        # user ID access
        good_uid = "test2 (test many subkeys) <test2@test2.test2>"
        test_uid = keymsg._b_userids[0].leader.body.value
        self.assertEqual(good_uid, test_uid)

    # Encountered a problem decrypting w/ DSAELG3 private key:
    # Since the private encryption key packet was not bound to the primary
    # key packet (no binding signature), the private encryption packet did not
    # show up as part of the secret key message (it's a leftover). This is a
    # good thing, and this test checks it.
    def testA02CatchUnboundSubblocks(self):
        "PublicKeyMsg: dismiss unbound private encryption key"
        key_d = read_test_file(['pgpfiles','key','DSAELG3.sec.nopass.gpg'])
        keymsg = list_msgs(list_pkts(key_d))[0]
        self.assertEqual(1, len(keymsg.seq())) # only one packet exists..
        keymsg._b_primary.leader.body.id # ..make sure it's the signing primary


#class A00PacketListTest(unittest.TestCase):
#    """Message Organization using organize_msgs()
#
#    Packet lists are organized in sublists according to the grammar which
#    defines them as being part of an OpenPGP message.
#    """
#
#    def setUp(self):
#        # since there's a bunch of list manipulation in the tests
#        self.single_empty_literal_msgs    = copy.deepcopy(single_empty_literal_msgs)
#        self.single_empty_compressed_msgs = copy.deepcopy(single_empty_compressed_msgs)
#        self.single_empty_encrypted_msgs  = copy.deepcopy(single_empty_encrypted_msgs)
#        self.single_empty_signed_msgs     = copy.deepcopy(single_empty_signed_msgs)
#        self.signest_onepass              = copy.deepcopy(signest_onepass)
#        self.signest_normal               = copy.deepcopy(signest_normal)
#                             
#    # check this against `gpg --list-packets`
#    def testA001ListPackets(self):
#        """message.list_pkts: check packets list order, type - public key"""
#        # this key file has known PGP packets in the following order:
#        #    public key(6), user id(13), signature(2), public subkey(14), 
#        #    signature(2)
#        pkts = list_pkts(dsapubkey_d)
#        self.assertEqual(pkts[0].tag.type, 6)
#        self.assertEqual(pkts[1].tag.type, 13)
#        self.assertEqual(pkts[2].tag.type, 2)
#        self.assertEqual(pkts[3].tag.type, 14)
#        self.assertEqual(pkts[4].tag.type, 2)
#    
#    # simple message organization
#    def testA01ListLiteral(self):
#        """message.organize_msgs: single literal message"""
#        for msg in self.single_empty_literal_msgs:
#            msgs = organize_msgs(msg[1])
#            self.assertEqual(msg[0], msgs[0][0][0])
#
#    def testA02ListCompressed(self):
#        """message.organize_msgs: single compressed message"""
#        for msg in self.single_empty_compressed_msgs:
#            msgs = organize_msgs(msg[1])
#            self.assertEqual(msg[0], msgs[0][0][0])
#    
#    def testA03ListEncrypted(self):
#        """message.organize_msgs: single encrypted message"""
#        for msg in self.single_empty_encrypted_msgs:
#            msgs = organize_msgs(msg[1])
#            self.assertEqual(msg[0], msgs[0][0][0])
#    
#    def testA04ListSigned(self):
#        """message.organize_msgs: single signed message"""
#        for msg in self.single_empty_signed_msgs:
#            msgs = organize_msgs(msg[1])
#            self.assertEqual(msg[0], msgs[0][0][0])
#    
#    def testA05ListLeftovers(self):
#        """message.organize_msgs: packet leftovers"""
#        for msgtype in [self.single_empty_literal_msgs,
#                        self.single_empty_compressed_msgs,
#                        self.single_empty_encrypted_msgs,
#                        self.single_empty_signed_msgs]:
#            for msg in msgtype:
#                msg[1].append(EMPTY.uid)
#                msg[1].append(EMPTY.uid)
#                msgs = organize_msgs(msg[1])
#                self.assertEqual(msg[0], msgs[0][0][0])
#                self.assertEqual(msgs[1][0].tag.type, EMPTY.uid.tag.type)
#                self.assertEqual(msgs[1][1].tag.type, EMPTY.uid.tag.type)
#                self.assertEqual(len(msgs[1]), 2)
#
#    def testA06ListMultiple_1(self):
#        """message.organize_msgs: multiple messages""" 
#        enc_msg = self.single_empty_encrypted_msgs[2]
#        sig_msg = self.single_empty_signed_msgs[1]
#        msgs = organize_msgs(enc_msg[1] + sig_msg[1]) 
#        self.assertEqual(msgs[0][0][0], enc_msg[0])
#        self.assertEqual(msgs[0][1][0], sig_msg[0])
#        self.assertEqual(len(msgs[1]), 0)
#
#    def testA07NestedOnePassSigs(self):
#        """message.organize_msgs: nested one-pass signatures""" 
#        sig_msgs = self.signest_onepass
#        for sig_msg in sig_msgs:
#            msgs = organize_msgs(sig_msg[1])
#            self.assertEqual(sig_msg[0], msgs[0][0][0])
#
#    def testA08NestedOnePassSigsLeftovers(self):
#        """message.organize_msgs: nested one-pass signatures with leftovers""" 
#        sig_msgs = self.signest_onepass
#        for sig_msg in sig_msgs:
#            sig_msg[1].append(EMPTY.sig) # add lone signature packet
#            msgs = organize_msgs(sig_msg[1])
#            self.assertEqual(sig_msg[0], msgs[0][0][0])
#            # identify lone signature packet as a leftover
#            self.assertEqual(msgs[1][0].tag.type, EMPTY.sig.tag.type)
#
#    def testA09NestedNormalSigs(self):
#        """message.organize_msgs: nested normal signatures""" 
#        sig_msgs = self.signest_normal
#        for sig_msg in sig_msgs:
#            msgs = organize_msgs(sig_msg[1])
#            self.assertEqual(sig_msg[0], msgs[0][0][0])
#
#    def testA10NestedNormalSigsLeftovers(self):
#        """message.organize_msgs: nested normal signatures with leftovers""" 
#        sig_msgs = self.signest_normal
#        for sig_msg in sig_msgs:
#            sig_msg[1].append(EMPTY.sig) # add lone signature packet
#            msgs = organize_msgs(sig_msg[1])
#            self.assertEqual(sig_msg[0], msgs[0][0][0])
#

if '__main__' == __name__:
    unittest.main()
