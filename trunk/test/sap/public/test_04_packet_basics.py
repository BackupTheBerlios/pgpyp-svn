"Basic packet tests"

import os
import unittest
import StringIO

# test targets
from openpgp.sap.pkt import Reserved, TestPGP
from openpgp.sap.pkt.Packet import Tag, create_Tag
from openpgp.sap.pkt.Packet import OldLength
from openpgp.sap.pkt.Packet import NewLength, create_NewLength
from openpgp.sap.pkt.Packet import create_Packet
import openpgp.sap.list as LIST

# package help
from openpgp.sap.exceptions import *

# test help
from support import read_test_file

class A0_TagDataTests(unittest.TestCase):
    """Tag: Check Tag data->attribute setting.

    Tag attributes are set automatically when an instance
    calls its set_data() method (ex. packet_tag.set_data('\x99') or 
    when its data attribute is set directly (packet_tag.data = '\x99')"""

    def testA0BadLeftBitSetData1(self):
        "Tag: left-most packet tag bit != 1 (00xxxxxx) (PGPFormatError)"
        self.assertRaises(PGPFormatError, Tag, '\x4a')

    def testA1BadLeftBitSetData2(self):
        "Tag: left-most packet tag bit != 1 (01xxxxxx) (PGPFormatError)"
        self.assertRaises(PGPFormatError, Tag, '\x6a')

    def testA2BadDataTypes(self):
        "Tag: bad data types (TypeError)"
        bad_types = [99, "mq", "\x99\x82", ["\x99"], {0:"\x99"}]
        bad_types = [99, ["\x99"], {0:"\x99"}]
        for d in bad_types:
            try:
                Tag(d)
            except TypeError:
                pass
            else:
                self.fail("expecting a TypeError for bad data type: ord=%s" % (str(ord(d))))

    def testA3BadDataValues(self):
        "Tag: bad data values (PGPFormatError)"
        bad_types = ["mq", "\x99\x82"]
        for d in bad_types:
            try:
                Tag(d)
            except PGPFormatError:
                pass
            else:
                self.fail("expecting a PGPFormatError for bad data type: ord=%s" % (str(ord(d))))

    def testB1InstantiateOld(self):
        "Tag: Instantiate old tags"
        old_packet_tags = [#reserved (type 0)
            {'data':"\x80", 'type':0, 'length_type':0, 'version':0, 'version_msg':"Old"}, # 1000 0000 
            {'data':"\x81", 'type':0, 'length_type':1, 'version':0, 'version_msg':"Old"}, # 1000 0001
            {'data':"\x82", 'type':0, 'length_type':2, 'version':0, 'version_msg':"Old"}, # 1000 0010
            {'data':"\x83", 'type':0, 'length_type':3, 'version':0, 'version_msg':"Old"}, # 1000 0011
                           #Public Key Packet (type 60
            {'data':"\x98", 'type':6, 'length_type':0, 'version':0, 'version_msg':"Old"}, # 1001 1000 
            {'data':"\x99", 'type':6, 'length_type':1, 'version':0, 'version_msg':"Old"}, # 1001 1001
            {'data':"\x9a", 'type':6, 'length_type':2, 'version':0, 'version_msg':"Old"}, # 1001 1010
            {'data':"\x9b", 'type':6, 'length_type':3, 'version':0, 'version_msg':"Old"}, # 1001 1011
                           # Trust Packet (type 12)
            {'data':"\xb0", 'type':12, 'length_type':0, 'version':0, 'version_msg':"Old"}, # 1011 0000
            {'data':"\xb1", 'type':12, 'length_type':1, 'version':0, 'version_msg':"Old"}, # 1011 0001
            {'data':"\xb2", 'type':12, 'length_type':2, 'version':0, 'version_msg':"Old"}, # 1011 0010
            {'data':"\xb3", 'type':12, 'length_type':3, 'version':0, 'version_msg':"Old"}, # 1011 0011
                           # Public Subkey Packet (type 14)
            {'data':"\xb8", 'type':14, 'length_type':0, 'version':0, 'version_msg':"Old"}, # 1011 1000
            {'data':"\xb9", 'type':14, 'length_type':1, 'version':0, 'version_msg':"Old"}, # 1011 1001
            {'data':"\xba", 'type':14, 'length_type':2, 'version':0, 'version_msg':"Old"}, # 1011 1010
            {'data':"\xbb", 'type':14, 'length_type':3, 'version':0, 'version_msg':"Old"}, # 1011 1011
                           # ?? (type 16)
            {'data':"\xbc", 'type':15, 'length_type':0, 'version':0, 'version_msg':"Old"}, # 1011 1100
            {'data':"\xbd", 'type':15, 'length_type':1, 'version':0, 'version_msg':"Old"}, # 1011 1101
            {'data':"\xbe", 'type':15, 'length_type':2, 'version':0, 'version_msg':"Old"}, # 1011 1110
            {'data':"\xbf", 'type':15, 'length_type':3, 'version':0, 'version_msg':"Old"}] # 1011 1111
        for tag_dict in old_packet_tags:
            tag = Tag(tag_dict['data'])
            ret = self.find_tag_diff(tag_dict, tag)
            if 0 != ret:
                err_msg = self.__tag_diff_err_msg(ret[0], ret[1], ret[2], ret[3])
                self.fail(err_msg)

    def testB2InstantiateNew(self):
        "Tag: Instantiate new tags"
        new_packet_tags = [
            {'data':"\xc0", 'type':0, 'version':1, 'version_msg':"New"}, # 1100 0000 reserved (type 0) 
            {'data':"\xc6", 'type':6, 'version':1, 'version_msg':"New"}, # 1100 0110 Public Key Packet (type 6) 
            {'data':"\xcc", 'type':12, 'version':1, 'version_msg':"New"}, # 1100 1100 Trust Packet type(12) 
            {'data':"\xe2", 'type':34, 'version':1, 'version_msg':"New"}, # 1110 0010 ?? (type 34) 
            {'data':"\xff", 'type':63, 'version':1, 'version_msg':"New"}] # 1111 1111 private or experimental (type 63) 
        for tag_dict in new_packet_tags:
            tag = Tag(tag_dict['data'])
            ret = self.find_tag_diff(tag_dict, tag)
            if 0 != ret:
                err_msg = self.__tag_diff_err_msg(ret[0], ret[1], ret[2], ret[3])
                self.fail(err_msg)

    def find_tag_diff(self, tag_dict, tag_obj):
        """Find a difference between given tag elements and a Tag's attributes.

        Returns 0 (no errors) or (data, attr, given, got)
        
        tag_dict is a dictionary of packet tag attributes, for example:
            'data':"\x99"       # hex string representing packet tag data
            'type':0            # packet type (reserved)  
            'version':0         # version (0 == old)
            'version_msg':'Old' # mixed-case string should match version
            'length_type':2     # length_type is only used for old packet tags

        tag_obj is an Tag object, presumably created using data
        from tag_dict['data'].

        Each element in the given dictionary is assumed to be consistent with
        the rest and is tested against the Tag object created with
        the dictionary's 'data'.

        The type_msg attribute is not being tested since it's an informal 
        message, likely to get changed.

        Return value is 0 if no errors are found or a tuple giving the 
        element's data (hex char), problematic attribute, the value provided
        for the attribute, and the value received from the created object.
        """ 
        if 0 == tag_dict['version']:
            attrs = ['type', 'version', 'length_type']
        elif 1 == tag_dict['version']:
            attrs = ['type', 'version']
        else:
            raise TypeError, "tag_dict['version'] must == 0 or 1."

        prob = 0
        for attr in attrs:
            if tag_dict[attr] != tag_obj.__dict__[attr]:
                prob = attr
                break
        if prob:
            return tag_dict['data'], prob, tag_dict[attr], tag_obj.__dict__[attr]
        else:
            return 0 

    def __tag_diff_err_msg(self, data, attr, given, got):
        "format a nice error message given a packet tag discrepancy"
        msg = """
            A discrepancy was found with packet tag (%s):
            attribute: %s
            received: %s
            found: %s""" % (str(hex(ord(data))), str(attr), str(given), str(got))
        return msg


class A1_TagCreation(unittest.TestCase):

    def testB01Creation(self):
        """Tag: create_Tag() "new" version"""
        for t in [0, 1, 34, 63]:
            tag = create_Tag(t)
            self.assertEqual(tag.type, t)
            self.assertEqual(len(tag._d), 1)
            self.assertEqual(ord(tag._d) & 192, 192) # new version
    
    def testB01CreationError(self):
        """Tag: create_Tag() "new" version out-of-bounds (PGPFormatError)"""
        self.assertRaises(PGPFormatError, create_Tag, 64)


# no creation tests
class B_OldLengthDataTests(unittest.TestCase):

    def testA1SetDataBadOcts(self):
        "OldLength: wrong number of octets (PGPFormatError)"
        wrongoctets = ["\x88\x88\x88", "\x88\x88\x88\x88\x88"]
        for w in wrongoctets:
            self.assertRaises(PGPFormatError, OldLength, w)

    def testA2SetDataBadTypes(self):
        "OldLength: wrong types (TypeError)"
        wrongtypes = [8, {0:"\x08"}]
        for w in wrongtypes:
            try:
                OldLength(w)
            except: # make sure something is raised
                pass
            else:
                raise

    def testB1SetDataCalc(self):
        "OldLength: check data/size integrity"
        # old lengths are straight decimal translations
        # and allow only 1, 2, or 4 octets
        goodlengths = [{'data':"\x00", 'size':0},
                       {'data':"\x08", 'size':8},
                       {'data':"\x0f", 'size':15},
                       {'data':"\x88", 'size':136},
                       {'data':"\xff", 'size':255},
                       {'data':"\x00\x00", 'size':0},
                       {'data':"\x1a\xad", 'size':6829},
                       {'data':"\x88\x88", 'size':34952},
                       {'data':"\x00\x00\x00\x00", 'size':0},
                       {'data':"\x34\xAC\xF9\x21", 'size':883751201},
                       {'data':"\xff\xff\xff\xff", 'size':4294967295}]
        for l in goodlengths:
            length = OldLength(l['data'])
            self.assertEqual(length.size, l['size'])


# TODO add tests for partial lengths
# TODO add tests for data2size
class C0_NewLengthDataTests(unittest.TestCase):

    def testA2SetDataBadTypes(self):
        "NewLength: wrong types (TypeError)"
        wrongtypes = [8, 8.2, unittest, {8:'\x08'}]
        for l in wrongtypes:
            self.assertRaises(TypeError, NewLength, l)

    def testA4SetDataEmpty(self):
        "NewLength: wrong types (PGPFormatError)"
        empties = ['', [], {}]
        for l in empties:
            self.assertRaises(PGPFormatError, NewLength, l)

    def testB1SetDataCalc(self):
        "NewLength: check data/size integrity"
        goodlengths = [# single octet, "normal" lengths 0-191
                       {'data':"\x00", 'size':0},
                       {'data':"\x88", 'size':136},
                       {'data':"\xbf", 'size':191},
                       # single octet, 2**X funky partial lengths 
                       {'data':"\xe0\x00", 'size':1},
                       {'data':"\xea\x00", 'size':1024},
                       {'data':"\xf4\x00", 'size':1048576},
                       {'data':"\xfe\x00", 'size':1073741824},
                       # double octet, see funky math in rfc2440
                       {'data':"\xc0\x00", 'size':192},
                       {'data':"\xc8\x01", 'size':2241},
                       {'data':"\xd2\x3e", 'size':4862},
                       {'data':"\xdf\xff", 'size':8383},
                       # pentuple octet, see more funky math in rfc2440
                       {'data':"\xff\x00\x00\x00\x00", 'size':0},
                       {'data':"\xff\xe2\x00\x45\x00", 'size':3791668480L},
                       {'data':"\xff\x92\xdf\x7c\xbb", 'size':2464119995L},
                       {'data':"\xff\xff\xff\xff\xff", 'size':4294967295L}]
        for l in goodlengths:
            length = NewLength(l['data'])
            self.assertEqual(length.size, l['size'])

class C1_NewLengthCreation(unittest.TestCase):
    """
    """
    def testB01create_NewLengthSanity(self):
        "NewLength: create_NewLength() size and octet restrictions"
        for l in [0, 45, 191]: # single octs
            newlength = create_NewLength(l)
            self.assertEqual(newlength.size, l)
            self.assertEqual(1, len(newlength._d))
        for l in [192, 4000, 8382]: # double octs
            newlength = create_NewLength(l)
            self.assertEqual(newlength.size, l)
            self.assertEqual(2, len(newlength._d))
        for l in [8383, 10000, 4294967295]: # pentocts
            newlength = create_NewLength(l)
            self.assertEqual(newlength.size, l)
            self.assertEqual(5, len(newlength._d))

    def testB02create_NewLengthValueError(self):
        "NewLength: create_NewLength() out-of-bounds (ValueError)"
        l = 4294967296
        self.assertRaises(PGPFormatError, create_NewLength, l)


body100  = read_test_file(['dummyfiles','yes100'])
body512  = read_test_file(['dummyfiles','yes512'])
body6k   = read_test_file(['dummyfiles','yes6k'])
body16k  = read_test_file(['dummyfiles','yes16k'])
body128k = read_test_file(['dummyfiles','yes128k'])

# tests for body size
# old packets use type 0, "Reserved"
good_old_pkts = [# len octs 1, len body 100
                ('\x80\x64' + body100, body100),
                # len octs 2, len body 16384
                ('\x81\x40\x00' + body16k, body16k),
                # len octs 4, len body 131072
                ('\x82\x00\x02\x00\x00' + body128k, body128k)]

# new packets use type 60, "private or experimental"
good_new_pkts = [# len octs 1, len body 100
            ('\xfc\x64' + body100, body100),
            # len octs 2, len body 6144
            ('\xfc\xd7\x40' + body6k, body6k),
            # len octs 5, len body 100
            ('\xfc' + '\xff\x00\x00\x00\x64' + body100, body100),
            # len octs 5, len body 131072
            ('\xfc' + '\xff\x00\x02\x00\x00' + body128k, body128k)]

partials = [# partial with normal ending, in sections of 512, 8, 8, 4, and 3
            ('\xfc'+'\xe9'+body512+'\xe3'+'\x01\x02\x03\x04\x05\x06\x07\x08'+'\xe3'+'\x01\x02\x03\x04\x05\x06\x07\x08'+'\xe2'+'\x01\x02\x03\x04'+'\x03'+'\x01\x02\x03', body512+'\x01\x02\x03\x04\x05\x06\x07\x08\x01\x02\x03\x04\x05\x06\x07\x08\x01\x02\x03\x04\x01\x02\x03'),
            # partial with zero length ending, in sections of 512, 16 and 2
            ('\xfc'+'\xe9'+body512+'\xe4'+'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10'+'\xe1'+'\x01\x02'+'\x00', body512+'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x01\x02')]

class D0_SimplePacketTest(unittest.TestCase):

    def testC0OldPackets(self):
        "Packet: old packet header length and body sanity"
        for p in good_old_pkts:
            pkt = Reserved.Reserved(p[0])
            self.assertEqual(pkt.body._d, p[1])

    def testC2NewPackets(self):
        "Packet: new packet header length and body sanity"
        for p in good_new_pkts:
            pkt = TestPGP.TestPGP(p[0])
            self.assertEqual(pkt.body._d, p[1])

    def testC2PartialPackets(self):
        "Packet: new packet partial lengths and body fragments sanity"
        for p in partials:
            pkt = TestPGP.TestPGP(p[0])
            self.assertEqual(pkt.body._d, p[1])

class D1_PacketCreation(unittest.TestCase):
    """
    """
    def testB01create_Packet(self):
        "Packet: create_Packet() using PublicKey instance"
        key_d = read_test_file(['pgpfiles','key','DSAELG1.pub.gpg'])
        keypkt = LIST.list_pkts(key_d)[0]
        pkttype = keypkt.tag.type
        body_d = keypkt.body._d
        newpkt = create_Packet(pkttype, body_d)
        # good once-over
        self.assertEqual(newpkt.tag.type, keypkt.tag.type)
        self.assertEqual(newpkt.length.size, keypkt.length.size) # ._d could differ
        self.assertEqual(newpkt.body._d, keypkt.body._d)

if '__main__' == __name__:
    unittest.main()
