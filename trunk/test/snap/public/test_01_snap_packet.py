"""Packet-centric tests

These tests make sure that packets and packet attributes act
properly. There are three kinds of tests:

    1. those common to `PGPPacketIO` instances. `TestPGPPacketIO`
       provides generic tests that every packet-thing must pass.
    2. those common to the subclass.
    3. those dependent on subclass attribute quirks.


To create new tests:
"""
# copy/paste this wherevers to get copy/pasteable hexstr output
# hexify = lambda s: ''.join(['\\x%s' % hex(ord(c))[2:].zfill(2) for c in s])
#
# Ex: hexify(raw_key_data)
#
# or check out sap, it might be in there

import unittest
import os

from openpgp.code import *
from openpgp.sap.util import strnum as STN

from openpgp.snap import packet

join = os.sep.join


class TestPGPPacketIO(unittest.TestCase):
    "Standard tests for all PGPPacketIO instances"
    def check_keys(self, good, test):
        for k in test:
            self.assertEqual(good[k], test[k])

    def check_pgpio(self, values, attrs, skip=None):
        print("")
        all_checks = [self.check_single_write,
                      self.check_chunky_write,
                      self.check_leftovers,
                      self.check_read_from_write,
                      self.check_read_from_attrs,
                      self.check_missing
                      ]
        if skip is not None:
            for method in skip:
                idx = all_checks.index(method)
                all_checks.pop(idx)
        for method in all_checks:
            method(values, attrs)
    
    def check_single_write(self, values, attrs):
        "write"
        print("\t..single write")
        i = self.i_class()
        i.write(values['bytes']) # write to instance
        t = attrs2dict(i, attrs) # get test attrs from it
        self.check_keys(values, t) # check 'um

    def check_chunky_write(self, values, attrs):
        "write chunks"
        print("\t..chunky write")
        i = self.i_class()
        for c in values['bytes']: # write to instance byte-wise
            i.write(c)
        t = attrs2dict(i, attrs) # get test attrs from it
        self.check_keys(values, t) # check 'um

    def check_read_from_write(self, values, attrs):
        "read from write"
        print("\t..read from write")
        i = self.i_class() # read-from
        j = self.i_class() # write-to
        i.write(values['bytes']) # fill up read-from instance
        j.write(i.read())
        t = attrs2dict(j, attrs) # get attrs from write-to
        self.check_keys(values, t) # check 'um

    def check_read_from_attrs(self, values, attrs):
        "read from attributes"
        print("\t..read from attrs")
        i = self.i_class() # read-from
        j = self.i_class() # write-to
        for name in attrs:
            setattr(i, name, values[name])
        j.write(i.read())
        t = attrs2dict(j, attrs)
        self.check_keys(values, t) # check 'um
        
    def check_leftovers(self, values, *a): # *a accept common params
        "check leftovers"
        print("\t..write w/ leftovers")
        i = self.i_class()
        x = "\xff\xff" # X-tra bytes
        l = i.write(values['bytes']+x) # should set leftovers
        self.assertEqual(l, x) # check 'um

    def check_missing(self, values, attrs):
        "check missing/awol"
        print("\t..check missing/awol attrs via write")
        len_attrs = len(attrs)
        idx = 0
        while idx <  len_attrs: # iterate up to each name in order
            i = self.i_class() # read-from
            j = self.i_class() # write-to
            missing_attrs = attrs[idx:] # remaining attrs to miss
            awol = attrs[idx]           # first missing name
            for name in attrs:
                if name not in missing_attrs: # go ahead and set it
                    setattr(i, name, values[name])
            j.write(i.read())
            self.assertEqual(j.awol(), awol) # check awol()
            for name in missing_attrs: # explicitly check attr err
                self.assertRaises(AttributeError, getattr, j, name)
            idx += 1


class Helpers(unittest.TestCase):

    def test_norm_text_lines_01(self):
        "packet.norm_text_lines: whole string"
        s = "\rone\r\ntwo\rthree\nfour\n"
        n = packet.norm_text_lines(s)
        self.assertEqual(n, "\r\none\r\ntwo\r\nthree\r\nfour\r\n")
    
    def test_norm_text_lines_02(self):
        "packet.norm_text_lines: partial string, known quirks"
        # the line from above, split at an ugly point
        s = "\rone\r", "\ntwo\rthree\nfour\n"
        n0 = packet.norm_text_lines(s[0])
        # the first chunk preserves a full right hand line ending
        self.assertEqual(n0, "\r\none\r\n")
        n1 = packet.norm_text_lines(s[1])
        # the second chunk preserves a full left hand line ending
        self.assertEqual(n1, "\r\ntwo\r\nthree\r\nfour\r\n")


class S2K(TestPGPPacketIO):
    i_class = packet.S2K

    def test_s2k_v3(self):
        "packet.S2K: type 3 S2K"
        values = {
            'bytes': "\x03\x02\xff\x07\xf5\x86\xdc\x61\x5e\x95\x60",
            # attrs
            'spec': 3,
            'k_hash': 2,
            'salt': "\xff\x07\xf5\x86\xdc\x61\x5e\x95",
            'count_code': 96,
            # method out
            'count': 65536}
        attrs = ['spec', 'k_hash', 'salt', 'count_code']
        #
        self.check_pgpio(values, attrs)
        #
        self.check_S2K(values, attrs)

    def check_S2K(self, values, attrs):
        self.check_count(values, attrs)

    def check_count(self, values, attrs):
        print("\t..get_count()")
        i = self.i_class()
        i.write(values['bytes'])
        self.assertEqual(values['count'], i.get_count())


#class B_01_PUBKEYSESKEY(unittest.TestCase): pass  


class Signature(TestPGPPacketIO):
    i_class = packet.Signature

    def test_v3a(self):
        "packet.Signature: v3 DSA SHA-1"
        values = {
            'bytes':"\x03\x05\x00\x3f\x0d\xfc\x90\x0c\xfc\x2b\x6d\xcc\x07\x9d\xf3\x11\x02\xe4\xa7\x00\xa0\x85\xd4\x02\xb1\xe2\xa3\xe9\x83\xd2\x42\x6d\x43\xa4\x1b\xc5\xf5\xf3\x21\xfb\xc9\x00\x9d\x1c\x77\x71\xc6\x2f\x4e\x5b\x7b\x42\x3b\xef\xc6\xa9\x8c\x4f\xed\x5d\xf5\x83\x24",
            # attrs
            'version':3,
            'v3_header_len':5,
            'type':0, # binary
            'k_asym':17, # DSA
            'k_hash':2, # SHA-1
            'v3_creation':1057881232,
            'v3_keyid':'0CFC2B6DCC079DF3',
            'check':'\xe4\xa7',
            'mpi':[764023765257466565036346295825866035266345630665,
                   162515441388792160507750767021459079594526475044]}
        attrs = ['version', 'v3_header_len', 'type', 'v3_creation',
                 'v3_keyid', 'k_asym', 'k_hash', 'check', 'mpi']
        self.check_pgpio(values, attrs)

    def test_v4a(self):
        "packet.Signature: v4 DSA SHA-1"
        values = {
            'bytes': "\x04\x13\x11\x02\x00\x1b\x05\x02\x3f\x07\x18\xfb\x06\x0b\x09\x08\x07\x03\x02\x03\x15\x02\x03\x03\x16\x02\x01\x02\x1e\x01\x02\x17\x80\x00\x0a\x09\x10\x0c\xfc\x2b\x6d\xcc\x07\x9d\xf3\x6c\xd6\x00\x9f\x74\x23\x4c\x70\xd3\x3b\xa2\xc6\xac\x57\xfb\xdf\xe5\xc8\x5e\xec\x39\x3d\x5b\x46\x00\x9f\x55\x60\x59\x88\xcd\x1d\x9e\xa7\xbd\x11\xe5\x15\x56\x3a\x38\x35\x20\x82\xf8\x73",
            # attrs
            'version': 4,
            'type': 0x13, # positive ID
            'k_asym': 17, # DSA
            'k_hash': 2, # SHA-1
            'hashed_subs_len': 27,
            'hashed_subs': [(1, 0, 2, 1057429755),
                          (1, 0, 11, [9, 8, 7, 3, 2]),
                          (1, 0, 21, [2, 3]),
                          (1, 0, 22, [2, 1]),
                          (1, 0, 30, [1]),
                          (1, 0, 23, [128])],
            'unhashed_subs_len': 10,
            'unhashed_subs': [(1, 0, 16, "0CFC2B6DCC079DF3")],
            'check': "\x6c\xd6",
            'mpi': [663030114423646619660992052365907314429386382150,
                    487412886603580660946127320316271328559024502899],
            # extraneous info (hidden in subpackets)
            'keyid': "0CFC2B6DCC079DF3"}
        attrs = ['version', 'type', 'k_asym', 'k_hash',
                 'hashed_subs_len', 'hashed_subs',
                 'unhashed_subs_len', 'unhashed_subs', 'check',
                 'mpi']
        self.check_pgpio(values, attrs)


class B_02a_SigSubs(unittest.TestCase):
    """Signature subpackets

    - check that byte-string conversions work properly - the tests just show
      what legal values look like and check to see if they can be recreation

    """
    lotta_subs_d = "\x05\x02\x3f\x07\x18\xfb\x06\x0b\x09\x08\x07\x03\x02\x03\x15\x02\x03\x03\x16\x02\x01\x02\x1e\x01\x02\x17\x80\x09\x10\x0c\xfc\x2b\x6d\xcc\x07\x9d\xf3"
    # all subs use 1-octet length specifier, none are critical
    lotta_subs = [(1, 0, 2, 1057429755),
                  (1, 0, 11, [9, 8, 7, 3, 2]),
                  (1, 0, 21, [2, 3]),
                  (1, 0, 22, [2, 1]),
                  (1, 0, 30, [1]),
                  (1, 0, 23, [128]),
                  (1, 0, 16, '0CFC2B6DCC079DF3')]

    def setUp(self):
        self.ss = packet.SigSubMill()

    def test01(self):
        "packet.SigSubMill: sub_bool conversion"
        for sub in [0, 1]:
            sub_d = self.ss.sub_bool2str(sub)
            sub_t = self.ss.str2sub_bool(sub_d)
            self.assertEqual(sub, sub_t)

    def test02(self):
        "packet.SigSubMill: sub_intbytes conversion"
        sub = [0, 1, 2, 3, 4] # integers only
        sub_d = self.ss.sub_intbytes2str(sub)
        sub_t = self.ss.str2sub_intbytes(sub_d)
        self.assertEqual(sub, sub_t)

    def test03(self):
        "packet.SigSubMill: sub_keyid conversion"
        sub = '0CFC2B6DCC079DF3'
        sub_d = self.ss.sub_keyid2str(sub)
        sub_t = self.ss.str2sub_keyid(sub_d)
        self.assertEqual(sub, sub_t)

    def test04a(self):
        "packet.SigSubMill: sub_note conversion"
        sub = ((0x80, 0, 0, 0), 'notename', 'notevalue')
        sub_d = self.ss.sub_note2str(sub)
        sub_t = self.ss.str2sub_note(sub_d)
        self.assertEqual(sub, sub_t)

    def test04b(self):
        "packet.SigSubMill: sub_note default flags"
        sub = (None, 'notename', 'notevalue')
        sub2 = ((0x80, 0, 0, 0), 'notename', 'notevalue')
        sub_d = self.ss.sub_note2str(sub)
        sub_t = self.ss.str2sub_note(sub_d)
        self.assertEqual(sub2, sub_t)

    def test05(self):
        "packet.SigSubMill: sub_revocreason conversion"
        sub = (3, 'revocation reason')
        sub_d = self.ss.sub_revocreason2str(sub)
        sub_t = self.ss.str2sub_revocreason(sub_d)
        self.assertEqual(sub, sub_t)

    def test06(self):
        "packet.SigSubMill: sub_revoker conversion"
        sub = (3, 17, '12345678901234567890')
        sub_d = self.ss.sub_revoker2str(sub)
        sub_t = self.ss.str2sub_revoker(sub_d)
        self.assertEqual(sub, sub_t)

    def test07(self):
        "packet.SigSubMill: sub_timestamp conversion"
        sub = 1057881232
        sub_d = self.ss.sub_timestamp2str(sub)
        sub_t = self.ss.str2sub_timestamp(sub_d)
        self.assertEqual(sub, sub_t)

    def test08(self):
        "packet.SigSubMill: sub_trust conversion"
        sub = (3, 4)
        sub_d = self.ss.sub_trust2str(sub)
        sub_t = self.ss.str2sub_trust(sub_d)
        self.assertEqual(sub, sub_t)

    def test10(self):
        "packet.SigSubMill: subpacket conversion"
        subs_d = self.ss.subs2str(self.lotta_subs)
        self.assertEqual(subs_d, self.lotta_subs_d)

    def test11(self):
        "packet.SigSubMill: subpacket string conversion"
        subs = self.ss.str2subs(self.lotta_subs_d)
        self.assertEqual(subs, self.lotta_subs)


#class B_03_SYMKEYSESKEY(unittest.TestCase): pass  
#class B_04_ONEPASS(unittest.TestCase): pass       


class PublicKey(TestPGPPacketIO):
    i_class = packet.PublicKey

    def test_v4dsa(self):
        "packet.PublicKey: v4 DSA"
        values = {'bytes':"\x04\x3f\x07\x18\xfb\x11\x04\x00\x9a\x07\x44\x09\x5f\xe4\x4b\x77\x50\x13\x5a\x51\x1c\xa9\x01\x9c\xbf\x5b\xda\xc7\xc6\x24\x8a\xd4\xfd\x90\x8a\x8d\xf6\x22\xcf\x3b\x1e\xe7\xfd\x9c\x38\x83\xc9\x30\x16\xf9\x35\x3a\x53\x88\x01\x99\xb4\x7a\x81\x77\x18\x9e\xf2\x4e\xc5\xef\x60\xa4\x6d\x65\x52\x41\x93\x27\x95\x50\xcb\x1b\xfc\x66\x2a\x19\x5b\x75\x6b\x50\xb9\x77\xc1\x81\x49\xc2\x0b\x9a\x71\xe9\x84\x58\x6c\xdb\x90\x8e\x9e\x79\xee\x6d\xb7\x4a\xbd\x96\x31\xdf\x94\xa0\x0b\x8f\xee\xda\x89\x08\x25\x31\x50\x75\x01\xad\x20\x87\x30\x59\x2a\x78\x92\x1f\xd5\x4f\x00\xa0\x89\x64\x64\x52\x79\xfa\x45\x51\x43\x79\x8b\x21\xf2\x29\x3b\x26\xdf\xc2\x67\x67\x03\xfd\x17\x69\x56\xd6\xd3\x1b\x89\xcc\xd1\x84\xb0\x28\xd5\xce\x04\x57\x91\xa7\xad\x0a\x90\xad\x2d\x9a\x53\x05\x24\x09\x74\xae\xc2\x1c\x19\xfa\x27\xa4\xc6\xcb\x27\xd7\xfb\x61\x81\xea\x3d\xa8\xb0\x3c\x4b\x25\x53\x54\x21\x68\xbb\x51\xb8\x66\x0a\x53\x24\x2d\x61\x74\x44\x76\x2a\x41\xb3\x07\xec\x49\x84\x3b\x81\x4d\x10\x1d\x99\x40\x93\x6c\xf6\x4d\x4a\xa3\xab\xcb\xd7\xeb\x98\xe3\x36\xf8\x1d\x91\x51\xb3\x47\x4e\xbf\xa2\x66\x5e\x36\x16\x65\xd7\x0e\x10\xd6\x4e\x93\x28\xe9\xd4\x26\x6a\x62\x54\xdb\x80\xf3\x25\xec\xee\xfc\xa1\x03\xff\x53\x4f\xd9\xf1\xb8\xd0\xcc\xb7\x3b\xcf\x59\x62\x3e\xe9\x07\x27\xf1\x6d\xb7\x70\xb5\x1c\xbf\x72\xf8\x32\x97\xdf\x1d\x77\x75\x9c\xfa\xe4\x48\xd2\x6f\x55\xac\xbf\x7e\x6e\x43\x23\x83\xe5\x75\xd6\xe2\x3a\xb0\x38\x74\x95\x3e\x32\x98\xa5\x39\x33\x95\xd1\xb0\x83\xb4\xf1\xc9\xfa\x3d\x59\x4d\xa0\x81\x9e\x51\xea\x4f\x38\xad\x75\x1a\xf0\x5f\x59\x49\x58\xbd\xa8\xe3\x54\x79\x75\x0c\x27\x03\x13\xda\x96\xc6\x9b\xf7\x30\x5d\xb7\x68\x27\x7d\x43\x68\x0e\x8b\x09\x04\xe8\xf6\x67\x1c\x51\x2f\x71\x49\x25\x88\x76\x56\xff\x5d\x75",
                  # attrs
                  'version':4, 
                  'creation': 1057429755,
                  'k_asym': 17,
                  'mpi': [108162408096535333017109092389191150504057999494127511277228051852128642002212300371475551654350536447053968257428460717965677101491932814302646981883822814178869523724022815326662763608015579727984865472158467803350744016249510202499023991753489746057425729064888749838340980532592524929254789779857453602127,
                          784370549416602408304947725338756815690347472743,
                          16440101261200658622067903127242601943814682673098800437898790070327551753434690524340448093346999385431361543977655437933271482723484845476562309592498510606974937474696095776038299765553949203192230189545951717115483657803995665348961526193203271219174774243349910858803481023135819075036450147258759838881,
                          58503619298725304490310186754546270249865616869728663777866074444008222890551802111175028184086919773021399154427691031465272730901597701887375618163233317525258518049576869357257484933866605721321613765903656789696262289087061100093910351894959991586479272473513161619690976796034067882384724056836533083509],
                  # PublicKey methods
                  'fingerprint':'4D04CE1D89B4995C26F85E620CFC2B6DCC079DF3',
                  'id':'0CFC2B6DCC079DF3'}
        attrs = ['version', 'creation', 'k_asym', 'mpi']
        self.check_pgpio(values, attrs)
        self.check_PublicKey(values, attrs)

    def test_v4rsa(self):
        "packet.PublicKey: v4 RSA"
        values = {'bytes':"\x04\x3f\x33\x95\xb3\x01\x04\x00\xd9\x92\xab\xf4\x78\xac\xe8\x70\xef\x57\x38\xf3\xa5\xac\xfc\x75\x5f\x85\xe6\x87\xf4\x69\x57\xf1\xa0\x14\x22\x05\x43\xd0\xb5\x06\xc6\x5e\xc7\xef\x3d\xf5\x02\xb0\x56\xa6\x74\xfe\xef\x97\x47\x03\x9b\x24\x32\xf8\x11\x35\x28\xf0\x62\x5d\x48\x77\xe5\x2e\xf3\x98\xb9\x4b\x60\x8e\x3c\xfd\xd1\x33\x2b\x4e\x17\xea\x6f\x07\xeb\x83\xe8\x21\xee\xf9\x34\xfb\x54\xe8\xd4\x54\xdd\xb5\x65\x10\x2b\x83\xd9\xdf\x0b\xa5\x6a\x30\xb5\xe0\xea\x15\x3c\x43\xf9\xd5\x6b\x7e\xbb\xa3\xeb\x29\x48\x67\xa7\xab\x8e\xed\x8b\x62\x7d\x73\xb2\xdf\x00\x06\x29",
                  # attrs
                 'version': 4,
                 'creation': 1060345267,
                 'k_asym': 1,
                 'mpi': [152784911704100476424986762597574795299505103739985174718360004853695170860585498933983550518165536176095201060108409979751437914738028121648007256554497223634511695495788070758051653175135201638291084392180573219151208680091077682983645639583211485405101398484520174387042448321673101737628828277284472599263,
                         41],
                 # PublicKey methods
                 'fingerprint':"AB06532F70BD5CD68978D0181AC964878A17BAC6",
                 'id':"1AC964878A17BAC6"}
        attrs = ['version', 'creation', 'k_asym', 'mpi']
        self.check_pgpio(values, attrs)
        self.check_PublicKey(values, attrs)

    def test_v3rsa(self):
        "packet.PublicKey: v3 RSA"
        values = {'bytes':"\x03\x3f\x34\x24\x81\x00\x00\x01\x08\x00\xad\x51\x50\xf5\x82\xe7\x7e\x84\x8d\x61\x61\x5c\x3f\x5c\x1c\x9c\x87\x04\xb7\xf1\xa1\x29\xb9\xd0\xe1\x2c\x76\xea\xe5\x76\xf3\x8d\x0a\xac\x90\xe8\xd6\x95\x29\x41\xd9\x49\x94\x72\x7d\x93\x91\x0c\x39\xb3\xc6\x34\x3f\x8f\xa0\x35\x38\xae\xfa\xd4\x72\x48\xf8\x96\x69\x1f\x4c\xfa\x6d\xdf\x7a\x18\x7e\x5a\xa9\x32\x4d\xf2\x24\x5f\xe6\x75\xa0\xce\x76\x23\x09\x33\x51\x05\x68\x69\xc1\x60\x8c\x1c\x58\x51\x0b\xe9\xb7\xf6\x42\x2f\xfe\xea\x85\xc3\x4f\x5e\xd2\xca\xd4\x44\x88\x6e\x8a\x04\x82\xbf\x71\x2c\x96\x20\x72\x54\x0d\xe2\x3c\x75\xa2\x4b\x01\x6e\x0e\x62\x50\x5a\xe6\xbf\x46\x91\x68\x36\x83\xf7\xb8\x0d\x15\x85\xef\x56\xd3\x05\x28\xdb\x5c\x00\x58\x6b\xb9\x16\xf2\xf8\xfa\xf8\x9b\xf2\x25\x41\x79\xbf\xa8\xa8\x3a\x04\x7e\x2e\x82\x89\xdb\x55\xa1\x9a\x9c\x56\x76\xc7\x8d\xb1\x26\x90\xcc\x2f\x93\x2d\x9f\x44\xae\x4b\x6d\xf3\x2d\xd4\x4d\x74\xda\x68\x6e\x38\xe5\x2a\xd1\xee\x78\xdc\x2e\x81\x4d\xb3\x12\x97\x39\x73\xbd\x90\x06\xbb\x5a\x78\x67\x80\xcb\x44\x62\x38\x22\xbc\x16\x27\xb1\x96\x27\x33\x93\xa2\xe1\x0a\xc4\x50\xc5\x32\x04\x50\x0d\x4d\x00\x05\x11",
                  # attrs
                  'version': 3,
                  'creation': 1060381825,
                  'v3_expiration': 0,
                  'k_asym': 1,
                  'mpi': [21879325294625117438469962136707825245725236592231094101539197962867441203308968438087867466717859926077820971617687165123982213332873777300020352409120032888581669605558175628997224986320961788100955646800135431419270236224241547322120677783462472436197006891488674090050752012730802593066503265420440374815255652563713162567579135474765268809166230065734402565621177809771312445305031287722787357140547196327472388803600323232225196720115732556508556390651612869353945233663894513147130986983402095041283378590517309021331224631164562618088015985246091280157157447223088717254478415401485435863234370460381900442957, 
                          17],
                  # PublicKey methods
                  'fingerprint':"F9921DF742D4892307578EF710B300C8",
                  'id':"C450C53204500D4D"}
        attrs = ['version', 'creation', 'v3_expiration', 'k_asym', 'mpi']
        self.check_pgpio(values, attrs)
        self.check_PublicKey(values, attrs)

    def check_key_id(self, values, *a):
        print("\t..get_id()")
        i = self.i_class()
        i.write(values['bytes'])
        self.assertEqual(values['id'], i.get_id() )

    _check_key_id = staticmethod(check_key_id)

    def check_fingerprint(self, values, *a):
        print("\t..get_fingerprint()")
        i = self.i_class()
        i.write(values['bytes'])
        self.assertEqual(values['fingerprint'], i.get_fingerprint())

    _check_fingerprint = staticmethod(check_fingerprint)

    def check_PublicKey(self, values, attrs):
        self.check_key_id(values, attrs)
        self.check_fingerprint(values, attrs)

class PrivateKey(TestPGPPacketIO):
    i_class = packet.PrivateKey

    def test_v4dsa_unencrypted(self):
        "packet.PrivateKey: v4 DSA unencrypted"
        values = {
                  'bytes': "\x04\x3f\x07\x18\xfb\x11\x04\x00\x9a\x07\x44\x09\x5f\xe4\x4b\x77\x50\x13\x5a\x51\x1c\xa9\x01\x9c\xbf\x5b\xda\xc7\xc6\x24\x8a\xd4\xfd\x90\x8a\x8d\xf6\x22\xcf\x3b\x1e\xe7\xfd\x9c\x38\x83\xc9\x30\x16\xf9\x35\x3a\x53\x88\x01\x99\xb4\x7a\x81\x77\x18\x9e\xf2\x4e\xc5\xef\x60\xa4\x6d\x65\x52\x41\x93\x27\x95\x50\xcb\x1b\xfc\x66\x2a\x19\x5b\x75\x6b\x50\xb9\x77\xc1\x81\x49\xc2\x0b\x9a\x71\xe9\x84\x58\x6c\xdb\x90\x8e\x9e\x79\xee\x6d\xb7\x4a\xbd\x96\x31\xdf\x94\xa0\x0b\x8f\xee\xda\x89\x08\x25\x31\x50\x75\x01\xad\x20\x87\x30\x59\x2a\x78\x92\x1f\xd5\x4f\x00\xa0\x89\x64\x64\x52\x79\xfa\x45\x51\x43\x79\x8b\x21\xf2\x29\x3b\x26\xdf\xc2\x67\x67\x03\xfd\x17\x69\x56\xd6\xd3\x1b\x89\xcc\xd1\x84\xb0\x28\xd5\xce\x04\x57\x91\xa7\xad\x0a\x90\xad\x2d\x9a\x53\x05\x24\x09\x74\xae\xc2\x1c\x19\xfa\x27\xa4\xc6\xcb\x27\xd7\xfb\x61\x81\xea\x3d\xa8\xb0\x3c\x4b\x25\x53\x54\x21\x68\xbb\x51\xb8\x66\x0a\x53\x24\x2d\x61\x74\x44\x76\x2a\x41\xb3\x07\xec\x49\x84\x3b\x81\x4d\x10\x1d\x99\x40\x93\x6c\xf6\x4d\x4a\xa3\xab\xcb\xd7\xeb\x98\xe3\x36\xf8\x1d\x91\x51\xb3\x47\x4e\xbf\xa2\x66\x5e\x36\x16\x65\xd7\x0e\x10\xd6\x4e\x93\x28\xe9\xd4\x26\x6a\x62\x54\xdb\x80\xf3\x25\xec\xee\xfc\xa1\x03\xff\x53\x4f\xd9\xf1\xb8\xd0\xcc\xb7\x3b\xcf\x59\x62\x3e\xe9\x07\x27\xf1\x6d\xb7\x70\xb5\x1c\xbf\x72\xf8\x32\x97\xdf\x1d\x77\x75\x9c\xfa\xe4\x48\xd2\x6f\x55\xac\xbf\x7e\x6e\x43\x23\x83\xe5\x75\xd6\xe2\x3a\xb0\x38\x74\x95\x3e\x32\x98\xa5\x39\x33\x95\xd1\xb0\x83\xb4\xf1\xc9\xfa\x3d\x59\x4d\xa0\x81\x9e\x51\xea\x4f\x38\xad\x75\x1a\xf0\x5f\x59\x49\x58\xbd\xa8\xe3\x54\x79\x75\x0c\x27\x03\x13\xda\x96\xc6\x9b\xf7\x30\x5d\xb7\x68\x27\x7d\x43\x68\x0e\x8b\x09\x04\xe8\xf6\x67\x1c\x51\x2f\x71\x49\x25\x88\x76\x56\xff\x5d\x75\x00\x00\x9d\x12\xb8\xdc\xbc\x17\x6d\xf3\xfe\x9e\x2a\xc1\x4e\x3c\x13\x13\xcf\x28\x1a\xf8\xba\x0a\x70",
                  # attrs
                  'version': 4,
                  'creation': 1057429755,
                  'k_asym': 17,
                  'mpi': [108162408096535333017109092389191150504057999494127511277228051852128642002212300371475551654350536447053968257428460717965677101491932814302646981883822814178869523724022815326662763608015579727984865472158467803350744016249510202499023991753489746057425729064888749838340980532592524929254789779857453602127,
                          784370549416602408304947725338756815690347472743,
                          16440101261200658622067903127242601943814682673098800437898790070327551753434690524340448093346999385431361543977655437933271482723484845476562309592498510606974937474696095776038299765553949203192230189545951717115483657803995665348961526193203271219174774243349910858803481023135819075036450147258759838881,
                          58503619298725304490310186754546270249865616869728663777866074444008222890551802111175028184086919773021399154427691031465272730901597701887375618163233317525258518049576869357257484933866605721321613765903656789696262289087061100093910351894959991586479272473513161619690976796034067882384724056836533083509],
                  's2k_usage': 0,
                  'mpi_private': [106884399698491867544003196898302249445319440570],
                  'chksum': "\x0a\x70",
                  # PublicKey methods
                  'fingerprint': "4D04CE1D89B4995C26F85E620CFC2B6DCC079DF3",
                  'id': "0CFC2B6DCC079DF3"}
        attrs = ['version', 'creation', 'k_asym', 'mpi', 's2k_usage',
                 'mpi_private', 'chksum']
        self.check_pgpio(values, attrs)
        self.check_PrivateKey(values, attrs)

    def test_v4dsa_s2k3(self):
        "packet.PrivateKey: v4 DSA w/ S2K type 3"
        s2k_values = {'spec': 3,
                      'k_hash': 2,
                      'salt': "\x17\xc6\xb2\x3d\x31\xa0\xe1\x63",
                      'count_code': 96,
                      # derived
                      'count': 65536}
        s2k = packet.S2K()
        for attr in ['spec', 'k_hash', 'salt', 'count_code']:
            setattr(s2k, attr, s2k_values[attr])
        values = {'bytes': "\x04\x3f\x07\x18\xfb\x11\x04\x00\x9a\x07\x44\x09\x5f\xe4\x4b\x77\x50\x13\x5a\x51\x1c\xa9\x01\x9c\xbf\x5b\xda\xc7\xc6\x24\x8a\xd4\xfd\x90\x8a\x8d\xf6\x22\xcf\x3b\x1e\xe7\xfd\x9c\x38\x83\xc9\x30\x16\xf9\x35\x3a\x53\x88\x01\x99\xb4\x7a\x81\x77\x18\x9e\xf2\x4e\xc5\xef\x60\xa4\x6d\x65\x52\x41\x93\x27\x95\x50\xcb\x1b\xfc\x66\x2a\x19\x5b\x75\x6b\x50\xb9\x77\xc1\x81\x49\xc2\x0b\x9a\x71\xe9\x84\x58\x6c\xdb\x90\x8e\x9e\x79\xee\x6d\xb7\x4a\xbd\x96\x31\xdf\x94\xa0\x0b\x8f\xee\xda\x89\x08\x25\x31\x50\x75\x01\xad\x20\x87\x30\x59\x2a\x78\x92\x1f\xd5\x4f\x00\xa0\x89\x64\x64\x52\x79\xfa\x45\x51\x43\x79\x8b\x21\xf2\x29\x3b\x26\xdf\xc2\x67\x67\x03\xfd\x17\x69\x56\xd6\xd3\x1b\x89\xcc\xd1\x84\xb0\x28\xd5\xce\x04\x57\x91\xa7\xad\x0a\x90\xad\x2d\x9a\x53\x05\x24\x09\x74\xae\xc2\x1c\x19\xfa\x27\xa4\xc6\xcb\x27\xd7\xfb\x61\x81\xea\x3d\xa8\xb0\x3c\x4b\x25\x53\x54\x21\x68\xbb\x51\xb8\x66\x0a\x53\x24\x2d\x61\x74\x44\x76\x2a\x41\xb3\x07\xec\x49\x84\x3b\x81\x4d\x10\x1d\x99\x40\x93\x6c\xf6\x4d\x4a\xa3\xab\xcb\xd7\xeb\x98\xe3\x36\xf8\x1d\x91\x51\xb3\x47\x4e\xbf\xa2\x66\x5e\x36\x16\x65\xd7\x0e\x10\xd6\x4e\x93\x28\xe9\xd4\x26\x6a\x62\x54\xdb\x80\xf3\x25\xec\xee\xfc\xa1\x03\xff\x53\x4f\xd9\xf1\xb8\xd0\xcc\xb7\x3b\xcf\x59\x62\x3e\xe9\x07\x27\xf1\x6d\xb7\x70\xb5\x1c\xbf\x72\xf8\x32\x97\xdf\x1d\x77\x75\x9c\xfa\xe4\x48\xd2\x6f\x55\xac\xbf\x7e\x6e\x43\x23\x83\xe5\x75\xd6\xe2\x3a\xb0\x38\x74\x95\x3e\x32\x98\xa5\x39\x33\x95\xd1\xb0\x83\xb4\xf1\xc9\xfa\x3d\x59\x4d\xa0\x81\x9e\x51\xea\x4f\x38\xad\x75\x1a\xf0\x5f\x59\x49\x58\xbd\xa8\xe3\x54\x79\x75\x0c\x27\x03\x13\xda\x96\xc6\x9b\xf7\x30\x5d\xb7\x68\x27\x7d\x43\x68\x0e\x8b\x09\x04\xe8\xf6\x67\x1c\x51\x2f\x71\x49\x25\x88\x76\x56\xff\x5d\x75\xfe\x03\x03\x02\x17\xc6\xb2\x3d\x31\xa0\xe1\x63\x60\x16\x68\xfb\xff\x97\x5d\x8a\x52\x8d\x86\xfb\x48\xd0\xf8\xc4\xe2\x99\x9c\x10\xa6\xfe\x50\x2f\xdb\x7d\x82\x06\xb7\x65\x64\xba\xc9\xa6\x32\x7e\x40\xa5\xc9\x54\x06\x59\x81\xbd\x6c\x2b\xa1\x60\x01\x7e\x50",
                  # attrs
                  'version': 4,
                  'creation': 1057429755,
                  'k_asym': 17,
                  'mpi': [108162408096535333017109092389191150504057999494127511277228051852128642002212300371475551654350536447053968257428460717965677101491932814302646981883822814178869523724022815326662763608015579727984865472158467803350744016249510202499023991753489746057425729064888749838340980532592524929254789779857453602127,
                          784370549416602408304947725338756815690347472743,
                          16440101261200658622067903127242601943814682673098800437898790070327551753434690524340448093346999385431361543977655437933271482723484845476562309592498510606974937474696095776038299765553949203192230189545951717115483657803995665348961526193203271219174774243349910858803481023135819075036450147258759838881,
                          58503619298725304490310186754546270249865616869728663777866074444008222890551802111175028184086919773021399154427691031465272730901597701887375618163233317525258518049576869357257484933866605721321613765903656789696262289087061100093910351894959991586479272473513161619690976796034067882384724056836533083509],
                  's2k_usage': 254,
                  'k_sym': 3,
                  's2k': s2k,
                  'iv': "\x16\x68\xfb\xff\x97\x5d\x8a\x52",
                  'mpi_encrypted': "\x8d\x86\xfb\x48\xd0\xf8\xc4\xe2\x99\x9c\x10\xa6\xfe\x50\x2f\xdb\x7d\x82\x06\xb7\x65\x64\xba\xc9\xa6\x32\x7e\x40\xa5\xc9\x54\x06\x59\x81\xbd\x6c\x2b\xa1\x60\x01\x7e\x50",
                  # PublicKey methods
                  'fingerprint': "4D04CE1D89B4995C26F85E620CFC2B6DCC079DF3",
                  'id': "0CFC2B6DCC079DF3"}
        attrs = ['version', 'creation', 'k_asym', 'mpi', 's2k_usage', 'k_sym',
                 's2k', 'iv', 'mpi_encrypted']
        skip = [self.check_leftovers, self.check_missing]
        self.check_pgpio(values, attrs, skip=skip)
        self.check_PrivateKey(values, attrs)

    def test_v3rsa_unencrypted(self):
        "packet.PrivateKey: v3 RSA unencrypted"
        values = {'bytes': "\x03\x3f\x34\x24\x81\x00\x00\x01\x08\x00\xad\x51\x50\xf5\x82\xe7\x7e\x84\x8d\x61\x61\x5c\x3f\x5c\x1c\x9c\x87\x04\xb7\xf1\xa1\x29\xb9\xd0\xe1\x2c\x76\xea\xe5\x76\xf3\x8d\x0a\xac\x90\xe8\xd6\x95\x29\x41\xd9\x49\x94\x72\x7d\x93\x91\x0c\x39\xb3\xc6\x34\x3f\x8f\xa0\x35\x38\xae\xfa\xd4\x72\x48\xf8\x96\x69\x1f\x4c\xfa\x6d\xdf\x7a\x18\x7e\x5a\xa9\x32\x4d\xf2\x24\x5f\xe6\x75\xa0\xce\x76\x23\x09\x33\x51\x05\x68\x69\xc1\x60\x8c\x1c\x58\x51\x0b\xe9\xb7\xf6\x42\x2f\xfe\xea\x85\xc3\x4f\x5e\xd2\xca\xd4\x44\x88\x6e\x8a\x04\x82\xbf\x71\x2c\x96\x20\x72\x54\x0d\xe2\x3c\x75\xa2\x4b\x01\x6e\x0e\x62\x50\x5a\xe6\xbf\x46\x91\x68\x36\x83\xf7\xb8\x0d\x15\x85\xef\x56\xd3\x05\x28\xdb\x5c\x00\x58\x6b\xb9\x16\xf2\xf8\xfa\xf8\x9b\xf2\x25\x41\x79\xbf\xa8\xa8\x3a\x04\x7e\x2e\x82\x89\xdb\x55\xa1\x9a\x9c\x56\x76\xc7\x8d\xb1\x26\x90\xcc\x2f\x93\x2d\x9f\x44\xae\x4b\x6d\xf3\x2d\xd4\x4d\x74\xda\x68\x6e\x38\xe5\x2a\xd1\xee\x78\xdc\x2e\x81\x4d\xb3\x12\x97\x39\x73\xbd\x90\x06\xbb\x5a\x78\x67\x80\xcb\x44\x62\x38\x22\xbc\x16\x27\xb1\x96\x27\x33\x93\xa2\xe1\x0a\xc4\x50\xc5\x32\x04\x50\x0d\x4d\x00\x05\x11\x00\x07\xfc\x08\x7e\xf7\x6b\x68\x4c\x9a\x47\xc0\xa7\xe9\x2a\x2b\x43\x42\xa8\x4c\xe4\x9f\x9a\xe7\x45\xcf\x62\x15\x13\xbf\x8e\x06\x3a\x89\x6d\xd0\xd6\x43\x56\xb5\x2f\x77\xfb\xb2\xce\xe6\xa6\x3d\x5f\x13\xa8\xc1\x92\xda\x07\x94\xaf\x32\x85\x1e\x62\xee\x2d\x8d\x21\xb1\xd5\x2d\x4f\x56\x98\xd3\x30\x9a\x10\x42\x6d\xdb\x1e\x12\xe1\x33\xfa\xa9\x6a\x28\x82\x97\x5c\x12\x05\x06\x7b\x3e\xd8\x01\xf3\x2a\x01\x63\xb3\xa8\xbd\xa7\x22\xa8\xe4\x3c\x2e\xa2\x2a\x33\x93\xb4\xff\xe7\x44\x9d\x46\xac\x69\xa2\x04\x5d\x64\x11\x65\xfb\x90\xab\x58\xd0\x2f\x3e\x64\xd2\xcf\x0a\x0c\xaf\x22\x41\xd5\xd4\xf8\xbb\xd6\x9e\x46\x63\x7b\x6f\x5e\x9e\x58\x08\x20\x16\x7f\x3e\x4d\x88\xc8\xe9\x16\xe2\x97\x05\x96\x22\x20\x1e\xac\xa1\x19\xd7\x05\xaf\x59\x2d\x28\x3b\xce\x09\xb3\xc6\xc5\x02\x5d\xc2\xdb\x1f\x80\x6b\x24\x18\x7b\x88\x74\x87\x7c\x1c\xd5\x17\xd5\x1d\xa2\x1e\xf3\x17\x1c\xf1\x2f\xe7\xf1\x97\x61\xe8\x26\x85\x57\xf8\xb5\x10\x44\x43\x59\x94\x91\x58\x79\xfa\xe5\xd7\x7e\x6d\xc0\x53\xb6\x65\x5b\xc7\xe0\x5b\xfb\x19\x86\x7c\xe4\x78\x7f\xf5\x45\x73\x91\xc7\xed\x35\x71\x04\x00\xcc\x07\x45\x85\xd8\xee\x4c\xef\x8a\x2b\x6a\x74\xa8\xe1\x35\xee\x1a\x36\xb7\x57\xca\x63\x58\x42\xea\xfc\x83\x54\xd5\x50\xad\x90\xb5\x28\x76\x73\xb4\x03\x78\xf7\x9c\x04\x98\xa7\x34\x4f\x5f\x3a\xbb\x51\xe5\x21\xcf\x51\x67\xa8\xa1\x43\x73\xe5\xf1\x26\x76\xca\xfe\x5c\x19\x3e\xd4\xd8\xf1\x78\xa8\xc4\x1e\xbe\xe9\x4e\x80\x5d\x50\x17\x85\xd5\xed\x48\x61\xf3\x0a\x7b\xe2\xaf\xf8\x97\x10\x93\xac\x32\x83\x54\x28\x85\x57\x8e\xf1\x70\x06\x7e\x13\x27\xa4\xb0\xb2\x94\x67\xf9\x95\x09\x8e\x54\x90\x66\x43\x5a\xa5\x32\x6d\x0d\x04\x00\xd9\x77\x63\xef\x8f\x33\x5a\xd6\x6b\x0e\x3d\x40\x71\xde\x07\x2e\x33\x58\x46\x78\xd1\x98\x5f\x43\x42\x46\xda\x95\xf6\x1b\x91\x3e\xd7\x4e\xd4\x7c\x6e\x98\x04\x6b\x4a\xae\x71\x09\x51\xe4\xe1\xae\x90\x0e\x3f\xc9\xac\x7d\x96\x3e\xfe\x00\xaf\x05\x19\xe8\x8c\x7f\x0d\x95\x00\xa5\x98\x21\x70\xa4\x78\x99\xe5\xc3\xb9\x94\x1c\x23\x19\x1c\xe3\xae\x07\xa5\x97\x0a\x83\xcf\x99\x62\x34\x8f\x97\xbc\xa0\xfb\xa9\xae\xcd\x3b\xe3\xde\xb4\x80\xe3\x31\x2f\x10\xea\x62\xdd\xcc\x1c\xe8\xd7\x97\xb8\x83\xdb\x94\xe5\xd3\x0a\x36\x91\x41\x03\xfe\x37\xe4\xa9\x41\x65\xa2\x88\x5e\xcc\x26\x93\xa8\xe6\xb2\x6c\x6c\xdd\x8e\x9f\x43\x19\x8c\xec\x19\x5e\x21\x72\x8e\x15\xb7\x5c\x42\x1e\x10\xfe\x31\x1b\xba\xa8\x47\xca\xf2\x1b\xcf\x6a\xd9\xa4\x10\xd5\x6c\x81\xf0\xec\xfb\xac\x93\x1d\x4c\x5d\x54\x0f\x3a\x39\x06\xca\x71\x89\xe0\x56\xfb\xfb\x3c\x48\x27\x52\xfa\xe6\xbd\x42\x7a\xd0\x33\x00\x17\x17\x2d\x2b\x68\xc3\x42\x67\x00\x4e\x3e\xcc\x02\x61\xf7\xf2\xde\x4c\x0a\x15\xa8\x57\x6e\xe0\x39\x5b\x9f\xc3\x5e\x82\xcd\x9e\x48\x74\x37\xbd\x82\x48\xfb\x07\x66\x96\x7d\x13\xe8\x38\xb2",
                  # attrs
                  'version': 3,
                  'creation': 1060381825,
                  'v3_expiration': 0,
                  'k_asym': 1,
                  'mpi': [21879325294625117438469962136707825245725236592231094101539197962867441203308968438087867466717859926077820971617687165123982213332873777300020352409120032888581669605558175628997224986320961788100955646800135431419270236224241547322120677783462472436197006891488674090050752012730802593066503265420440374815255652563713162567579135474765268809166230065734402565621177809771312445305031287722787357140547196327472388803600323232225196720115732556508556390651612869353945233663894513147130986983402095041283378590517309021331224631164562618088015985246091280157157447223088717254478415401485435863234370460381900442957,
                          17],
                  's2k_usage': 0,
                  'mpi_private': [1072515945814956737179900104740579668908099832952504612820548919748403980554361197945483699348914702258716714294984664957057951633964400848040213353388236906303023019880302726911628675800047146475537041509810560363689717461972624868731405773699140805695931710367091867159350588859353068287573689481394136020341160238642841839605549148164725228909883515060421046822933713239968482893069420603680860081401739306739301033483434902704280125028169466744411549476738484491804515989234167393100038751725226631568852962989673206836895258470183610058985070574477882385666137363775705735175224397287384442633332292787786036593,
                                  143273618061810626683549903919050179965918557397995931865235060179695280009295365499909812502062662220340489893121443322712019174952255352715131911357568868523349353598320348044866783614409203336552190963217172640410322471813416566320813890659720229395711925010837880852359359503399323277162222994252543192333,
                                  152710077337378412942382948285823959438687801103817278568094999496260114277119741907787998977889052249650157827416807894345862994588820082207428869968578917197783753885197150283023412833798268420726587182310802961448238886559400406563906654867022250093856319991226439404544478193423469956352168693258522104129,
                                  39249545174940744197862700705624409169811535844260962713609420034714587285907030172325685700475007826359956547025852631932976944240159584360916676762165297824226867649810614317781461712660830224084673977488205670330317560430301229870074041169129891112785113923807115857314440009992640990257723123744445895656],
                  'chksum': "\x38\xb2",
                  # PublicKey methods
                  'fingerprint': "F9921DF742D4892307578EF710B300C8",
                  'id': "C450C53204500D4D"}
        attrs = ['version', 'creation', 'v3_expiration', 'k_asym', 'mpi',
                 's2k_usage', 'mpi_private', 'chksum']
        self.check_pgpio(values, attrs) # no skippage
        self.check_PrivateKey(values, attrs)

    def test_v4rsa_s2k3(self):
        "packet.PrivateKey: v4 RSA w/ S2K type 3"
        s2k_values = {'spec': 3,
                      'k_hash': 2,
                      'salt': "\xff\x07\xf5\x86\xdc\x61\x5e\x95",
                      'count_code': 96,
                      'count': 65536}
        s2k = packet.S2K()
        for attr in ['spec', 'k_hash', 'salt', 'count_code']:
            setattr(s2k, attr, s2k_values[attr])
        values = {'bytes': "\x04\x3f\x33\x95\xb3\x01\x04\x00\xd9\x92\xab\xf4\x78\xac\xe8\x70\xef\x57\x38\xf3\xa5\xac\xfc\x75\x5f\x85\xe6\x87\xf4\x69\x57\xf1\xa0\x14\x22\x05\x43\xd0\xb5\x06\xc6\x5e\xc7\xef\x3d\xf5\x02\xb0\x56\xa6\x74\xfe\xef\x97\x47\x03\x9b\x24\x32\xf8\x11\x35\x28\xf0\x62\x5d\x48\x77\xe5\x2e\xf3\x98\xb9\x4b\x60\x8e\x3c\xfd\xd1\x33\x2b\x4e\x17\xea\x6f\x07\xeb\x83\xe8\x21\xee\xf9\x34\xfb\x54\xe8\xd4\x54\xdd\xb5\x65\x10\x2b\x83\xd9\xdf\x0b\xa5\x6a\x30\xb5\xe0\xea\x15\x3c\x43\xf9\xd5\x6b\x7e\xbb\xa3\xeb\x29\x48\x67\xa7\xab\x8e\xed\x8b\x62\x7d\x73\xb2\xdf\x00\x06\x29\xfe\x03\x03\x02\xff\x07\xf5\x86\xdc\x61\x5e\x95\x60\x0b\xfd\x02\xa7\x70\x7b\x99\xbe\xc7\x44\x18\x7d\x9a\x96\x27\x22\x37\x77\xdb\x21\x2b\x08\x7e\x1f\x63\x57\xc2\xf0\xea\x7a\x8b\xf6\x17\xff\xb4\x5a\x9d\xb9\x67\x67\x0b\xe0\xb0\x15\xaa\x8c\xd7\xeb\x7e\xf0\x0c\x37\x3c\xab\x46\x1d\xc4\x81\x69\xcc\xd6\x13\x51\x52\x7c\x55\xc4\xe2\xcb\xa3\x72\xd5\x34\xc6\xb1\x9b\xc4\x74\xd9\x0a\x2d\x66\x6d\xf5\x1f\xf6\xb3\x18\x7b\x9f\x4f\x4e\x78\x88\xce\xc6\x61\x92\xb8\xb0\xa9\x27\xa8\x92\x58\x13\xb8\xbf\xbc\xb6\x30\x38\xd8\xc3\x04\xe8\x6b\x21\x52\x01\xfe\x42\x07\x0e\x58\x90\x4a\x5f\xb9\xbc\x5e\x21\x5b\x89\x30\x7d\x53\x6e\x54\x50\x00\xff\xf6\x42\xf2\x56\xe5\xe5\x94\xe3\x5e\x25\x8f\x63\x2d\x94\xe1\xc3\xf5\x49\xbe\xc8\x65\xb5\x77\xa2\x85\x04\x1a\x30\xe7\x01\xe4\x8a\x59\x03\x5e\x0f\x49\xbd\x0d\xd1\xe2\xc7\x27\xe7\x65\x72\x9f\x28\x3e\x35\xb6\xbf\x63\x00\x54\xa7\x72\xb8\x41\xaf\xc0\xb6\x88\xe5\x64\x18\xa1\x1f\x66\x0b\xda\xbb\xaf\x27\x94\x38\xf6\xac\x88\xc8\xaa\xa1\xfe\x5d\xa7\x1b\x91\x00\xeb\xb5\xc9\xaa\xe3\x8d\xc6\x87\x7b\xe4\x4f\x70\x81\x84\xbd\x2c\x9d\x42\xdc\x5c\x44\xb8\x37\xdd\x22\xd8\xaa\x1b\x95\xc8\x32\xf1\x23\x70\x19\x87\x16\xab\x98\x17\x0d\x65\xb8\x0e\x17\x59\x4a\x5a\xed\xa1\x53\xfc\x3e\x0e\x3a\xe0\x7d\x54\xb6\xf6\xca\x00\x1d\xb3\x6c\xd3\x93\xc4\x3a\xca\xba\x5d\x38\x11\xdf\xae\xb7\xcf\xa1\xc3\x57\xaf\x3f\xc6\xf4\x9f\xa6\x55\xe7\x96\xb4\xc6\x84\xf8\x7f\x63\xcc\x78\x06\x3f\x35\x8b\xc4\xe0\x0f\x63\xd8\x8a\x7a\x4d\x61\x85\x14\x23\xd3\x2f\x0f\xf1\x9b\xe2\x58\x83\x92\x9e\xf5\x9a",
                  # attrs
                  'version': 4,
                  'creation': 1060345267,
                  'k_asym': 1,
                  'mpi': [152784911704100476424986762597574795299505103739985174718360004853695170860585498933983550518165536176095201060108409979751437914738028121648007256554497223634511695495788070758051653175135201638291084392180573219151208680091077682983645639583211485405101398484520174387042448321673101737628828277284472599263,
                          41],
                  's2k_usage': 254,
                  'k_sym': 3,
                  's2k': s2k,
                  'iv': "\x0b\xfd\x02\xa7\x70\x7b\x99\xbe",
                  'mpi_encrypted': "\xc7\x44\x18\x7d\x9a\x96\x27\x22\x37\x77\xdb\x21\x2b\x08\x7e\x1f\x63\x57\xc2\xf0\xea\x7a\x8b\xf6\x17\xff\xb4\x5a\x9d\xb9\x67\x67\x0b\xe0\xb0\x15\xaa\x8c\xd7\xeb\x7e\xf0\x0c\x37\x3c\xab\x46\x1d\xc4\x81\x69\xcc\xd6\x13\x51\x52\x7c\x55\xc4\xe2\xcb\xa3\x72\xd5\x34\xc6\xb1\x9b\xc4\x74\xd9\x0a\x2d\x66\x6d\xf5\x1f\xf6\xb3\x18\x7b\x9f\x4f\x4e\x78\x88\xce\xc6\x61\x92\xb8\xb0\xa9\x27\xa8\x92\x58\x13\xb8\xbf\xbc\xb6\x30\x38\xd8\xc3\x04\xe8\x6b\x21\x52\x01\xfe\x42\x07\x0e\x58\x90\x4a\x5f\xb9\xbc\x5e\x21\x5b\x89\x30\x7d\x53\x6e\x54\x50\x00\xff\xf6\x42\xf2\x56\xe5\xe5\x94\xe3\x5e\x25\x8f\x63\x2d\x94\xe1\xc3\xf5\x49\xbe\xc8\x65\xb5\x77\xa2\x85\x04\x1a\x30\xe7\x01\xe4\x8a\x59\x03\x5e\x0f\x49\xbd\x0d\xd1\xe2\xc7\x27\xe7\x65\x72\x9f\x28\x3e\x35\xb6\xbf\x63\x00\x54\xa7\x72\xb8\x41\xaf\xc0\xb6\x88\xe5\x64\x18\xa1\x1f\x66\x0b\xda\xbb\xaf\x27\x94\x38\xf6\xac\x88\xc8\xaa\xa1\xfe\x5d\xa7\x1b\x91\x00\xeb\xb5\xc9\xaa\xe3\x8d\xc6\x87\x7b\xe4\x4f\x70\x81\x84\xbd\x2c\x9d\x42\xdc\x5c\x44\xb8\x37\xdd\x22\xd8\xaa\x1b\x95\xc8\x32\xf1\x23\x70\x19\x87\x16\xab\x98\x17\x0d\x65\xb8\x0e\x17\x59\x4a\x5a\xed\xa1\x53\xfc\x3e\x0e\x3a\xe0\x7d\x54\xb6\xf6\xca\x00\x1d\xb3\x6c\xd3\x93\xc4\x3a\xca\xba\x5d\x38\x11\xdf\xae\xb7\xcf\xa1\xc3\x57\xaf\x3f\xc6\xf4\x9f\xa6\x55\xe7\x96\xb4\xc6\x84\xf8\x7f\x63\xcc\x78\x06\x3f\x35\x8b\xc4\xe0\x0f\x63\xd8\x8a\x7a\x4d\x61\x85\x14\x23\xd3\x2f\x0f\xf1\x9b\xe2\x58\x83\x92\x9e\xf5\x9a",
                  # PublicKey methods
                  'fingerprint': "AB06532F70BD5CD68978D0181AC964878A17BAC6",
                  'id': "1AC964878A17BAC6"
                  }
        attrs = ['version', 'creation', 'k_asym', 'mpi', 's2k_usage', 'k_sym',
                 's2k', 'iv', 'mpi_encrypted']
        skip = [self.check_leftovers, self.check_missing]
        self.check_pgpio(values, attrs, skip=skip)
        self.check_PrivateKey(values, attrs)

    def check_PrivateKey(self, values, attrs):
        PublicKey._check_key_id(self, values, attrs)
        PublicKey._check_fingerprint(self, values, attrs)


class PublicSubkey(TestPGPPacketIO):
    i_class = packet.PublicSubkey

    def test_v4elg(self):
        "packet.PublicSubkey: v4 ElGamal"
        values = {'bytes': "\x04\x3f\x34\x0d\x85\x10\x08\x00\xf6\x42\x57\xb7\x08\x7f\x08\x17\x72\xa2\xba\xd6\xa9\x42\xf3\x05\xe8\xf9\x53\x11\x39\x4f\xb6\xf1\x6e\xb9\x4b\x38\x20\xda\x01\xa7\x56\xa3\x14\xe9\x8f\x40\x55\xf3\xd0\x07\xc6\xcb\x43\xa9\x94\xad\xf7\x4c\x64\x86\x49\xf8\x0c\x83\xbd\x65\xe9\x17\xd4\xa1\xd3\x50\xf8\xf5\x59\x5f\xdc\x76\x52\x4f\x3d\x3d\x8d\xdb\xce\x99\xe1\x57\x92\x59\xcd\xfd\xb8\xae\x74\x4f\xc5\xfc\x76\xbc\x83\xc5\x47\x30\x61\xce\x7c\xc9\x66\xff\x15\xf9\xbb\xfd\x91\x5e\xc7\x01\xaa\xd3\x5b\x9e\x8d\xa0\xa5\x72\x3a\xd4\x1a\xf0\xbf\x46\x00\x58\x2b\xe5\xf4\x88\xfd\x58\x4e\x49\xdb\xcd\x20\xb4\x9d\xe4\x91\x07\x36\x6b\x33\x6c\x38\x0d\x45\x1d\x0f\x7c\x88\xb3\x1c\x7c\x5b\x2d\x8e\xf6\xf3\xc9\x23\xc0\x43\xf0\xa5\x5b\x18\x8d\x8e\xbb\x55\x8c\xb8\x5d\x38\xd3\x34\xfd\x7c\x17\x57\x43\xa3\x1d\x18\x6c\xde\x33\x21\x2c\xb5\x2a\xff\x3c\xe1\xb1\x29\x40\x18\x11\x8d\x7c\x84\xa7\x0a\x72\xd6\x86\xc4\x03\x19\xc8\x07\x29\x7a\xca\x95\x0c\xd9\x96\x9f\xab\xd0\x0a\x50\x9b\x02\x46\xd3\x08\x3d\x66\xa4\x5d\x41\x9f\x9c\x7c\xbd\x89\x4b\x22\x19\x26\xba\xab\xa2\x5e\xc3\x55\xe9\x32\x0b\x3b\x00\x02\x02\x07\xff\x6c\x58\x2c\x8a\xd9\xfb\x04\x86\x9c\xfc\xbc\x27\x71\x5a\xca\x0b\x79\xcc\x62\xf9\x87\x63\x49\x68\x04\x4e\x36\x53\x86\xf9\xb5\x82\x2f\x19\x98\xeb\x8a\x00\xfe\x93\x45\x52\xd5\xd9\x5a\x63\xf5\xc8\x87\xf0\x52\x17\x8e\x26\x7e\xf7\x6b\x16\x5f\xe3\xe5\x97\x0e\x8d\xdd\xff\x85\x1e\x02\xda\xd1\x0a\x8d\x0e\x12\xc4\x3e\xa7\x03\x59\x14\x62\x17\xbf\x07\x73\x7b\xe9\x2a\xb5\x36\x7c\x2b\x80\x70\xb9\xc3\xaa\x84\x8a\x07\xbb\x2a\xa0\xbb\x87\xeb\x61\xf7\x04\x8b\x07\x09\x2f\x96\x42\x31\x9b\x65\xee\x3b\xde\xfc\xc0\x1a\x60\x67\x71\x03\x41\x58\xa6\x27\x52\x42\xb7\x11\x27\xed\x12\x63\x5e\xaa\x3f\xdc\x3e\xf9\x8f\x53\xb5\x24\x3f\x9d\x09\x09\x10\xf4\x16\x87\x23\xf6\x7e\xc0\x94\x44\xd1\xd1\x4c\x1b\x02\xe7\x8f\xd5\x82\x6c\x40\x1a\x00\x85\x1f\xe7\xbf\x57\x3d\xf8\x07\xf8\x9d\x15\xea\xdf\x47\xd5\x4c\x97\x42\xdd\x3f\x0c\x7f\x5e\xa4\xbd\x75\x33\x3f\x08\x45\x9a\x61\xe0\x05\x01\x3b\xed\xea\x2d\xeb\x50\x9e\x70\x05\xbc\x98\x79\x03\xec\x38\xff\xda\x1c\x44\x6c\x42\x32\x14\x8b\x56\x69\xa9\xc9\x27\x06\xb5\x75\x9a\xd0\xd6\x4e\x1e\xdd\x49\xe6\x59\x88\x1e",
                  # attrs
                  'version': 4, 
                  'creation': 1060375941,
                  'k_asym': 16,
                  'mpi': [31087337795061487877547416545715496334920954980132212151448781444321393445568157959166911302972918628838917381555939620290244963511997037011253946065678925033455872043721454426215650798450188675325621498188688302603627388365642425546473761584899398546726625631228589029183157123265299738241899897560139599077166257814263354432724020387267456594044458497157226037520021564951601668256091905149808373739011153824316842260356584928931097012930709279713696588076097146536216639697002502410139891180002231258705541413293860269631209702305813614701588402302998104362562812340366960005570331931340105075488237470969553357627,
                          2,
                          13677217153160408116756482218665978246151329378802713550993307207471816940256331567699687384669466691582592352425552829806507488521715086009498475702710656178734469877407118257986414662736706529807517784982617057098081131342879985598241116865962182302248072153431236685823064649392899770528114019332463847236450731666302055534717271751161307279444324196420596233165771075662570201936819487176789243435454609296235924663430459843581194706772343053644585006691657943637200505874174079273145779265324403369833705430908627929204732075490226380388010366074406248900633161750067221657319224901070155720597206041500749236254],
                  # PublicKey methods
                  'fingerprint': "BAA202EB932697BCFCF03C9171345307625343E8",
                  'id': "71345307625343E8"}
        attrs = ['version', 'creation', 'k_asym', 'mpi']
        self.check_pgpio(values, attrs)
        self.check_PublicSubkey(values, attrs)

    def check_PublicSubkey(self, values, attrs):
        PublicKey._check_key_id(self, values, attrs)
        PublicKey._check_fingerprint(self, values, attrs)


class PrivateSubkey(TestPGPPacketIO):
    i_class = packet.PrivateSubkey

    def test_v3elg_unencrypted(self):
        "packet.PrivateSubkey: v4 ElGamal unencrypted"
        values = {
                  'bytes': "\x04\x3f\x34\x0d\x85\x10\x08\x00\xf6\x42\x57\xb7\x08\x7f\x08\x17\x72\xa2\xba\xd6\xa9\x42\xf3\x05\xe8\xf9\x53\x11\x39\x4f\xb6\xf1\x6e\xb9\x4b\x38\x20\xda\x01\xa7\x56\xa3\x14\xe9\x8f\x40\x55\xf3\xd0\x07\xc6\xcb\x43\xa9\x94\xad\xf7\x4c\x64\x86\x49\xf8\x0c\x83\xbd\x65\xe9\x17\xd4\xa1\xd3\x50\xf8\xf5\x59\x5f\xdc\x76\x52\x4f\x3d\x3d\x8d\xdb\xce\x99\xe1\x57\x92\x59\xcd\xfd\xb8\xae\x74\x4f\xc5\xfc\x76\xbc\x83\xc5\x47\x30\x61\xce\x7c\xc9\x66\xff\x15\xf9\xbb\xfd\x91\x5e\xc7\x01\xaa\xd3\x5b\x9e\x8d\xa0\xa5\x72\x3a\xd4\x1a\xf0\xbf\x46\x00\x58\x2b\xe5\xf4\x88\xfd\x58\x4e\x49\xdb\xcd\x20\xb4\x9d\xe4\x91\x07\x36\x6b\x33\x6c\x38\x0d\x45\x1d\x0f\x7c\x88\xb3\x1c\x7c\x5b\x2d\x8e\xf6\xf3\xc9\x23\xc0\x43\xf0\xa5\x5b\x18\x8d\x8e\xbb\x55\x8c\xb8\x5d\x38\xd3\x34\xfd\x7c\x17\x57\x43\xa3\x1d\x18\x6c\xde\x33\x21\x2c\xb5\x2a\xff\x3c\xe1\xb1\x29\x40\x18\x11\x8d\x7c\x84\xa7\x0a\x72\xd6\x86\xc4\x03\x19\xc8\x07\x29\x7a\xca\x95\x0c\xd9\x96\x9f\xab\xd0\x0a\x50\x9b\x02\x46\xd3\x08\x3d\x66\xa4\x5d\x41\x9f\x9c\x7c\xbd\x89\x4b\x22\x19\x26\xba\xab\xa2\x5e\xc3\x55\xe9\x32\x0b\x3b\x00\x02\x02\x07\xff\x6c\x58\x2c\x8a\xd9\xfb\x04\x86\x9c\xfc\xbc\x27\x71\x5a\xca\x0b\x79\xcc\x62\xf9\x87\x63\x49\x68\x04\x4e\x36\x53\x86\xf9\xb5\x82\x2f\x19\x98\xeb\x8a\x00\xfe\x93\x45\x52\xd5\xd9\x5a\x63\xf5\xc8\x87\xf0\x52\x17\x8e\x26\x7e\xf7\x6b\x16\x5f\xe3\xe5\x97\x0e\x8d\xdd\xff\x85\x1e\x02\xda\xd1\x0a\x8d\x0e\x12\xc4\x3e\xa7\x03\x59\x14\x62\x17\xbf\x07\x73\x7b\xe9\x2a\xb5\x36\x7c\x2b\x80\x70\xb9\xc3\xaa\x84\x8a\x07\xbb\x2a\xa0\xbb\x87\xeb\x61\xf7\x04\x8b\x07\x09\x2f\x96\x42\x31\x9b\x65\xee\x3b\xde\xfc\xc0\x1a\x60\x67\x71\x03\x41\x58\xa6\x27\x52\x42\xb7\x11\x27\xed\x12\x63\x5e\xaa\x3f\xdc\x3e\xf9\x8f\x53\xb5\x24\x3f\x9d\x09\x09\x10\xf4\x16\x87\x23\xf6\x7e\xc0\x94\x44\xd1\xd1\x4c\x1b\x02\xe7\x8f\xd5\x82\x6c\x40\x1a\x00\x85\x1f\xe7\xbf\x57\x3d\xf8\x07\xf8\x9d\x15\xea\xdf\x47\xd5\x4c\x97\x42\xdd\x3f\x0c\x7f\x5e\xa4\xbd\x75\x33\x3f\x08\x45\x9a\x61\xe0\x05\x01\x3b\xed\xea\x2d\xeb\x50\x9e\x70\x05\xbc\x98\x79\x03\xec\x38\xff\xda\x1c\x44\x6c\x42\x32\x14\x8b\x56\x69\xa9\xc9\x27\x06\xb5\x75\x9a\xd0\xd6\x4e\x1e\xdd\x49\xe6\x59\x88\x1e\x00\x01\x50\x9a\xc8\xad\xcb\xd0\x8d\xff\xf9\x9b\x09\x62\x8a\xf7\x58\x8e\x7b\xf9\xff\x10\x9a\x01\x04\x01\x70\xaa\x35\x41\x75\xfd\x7d\x3a\x4e\xf8\x0b\x8f\x8f\xd6\xe6\xcb\xe7\x4e\x02\x16\xf6",
                  # attrs
                  'version': 4,
                  'creation': 1060375941,
                  'k_asym': 16,
                  'mpi': [31087337795061487877547416545715496334920954980132212151448781444321393445568157959166911302972918628838917381555939620290244963511997037011253946065678925033455872043721454426215650798450188675325621498188688302603627388365642425546473761584899398546726625631228589029183157123265299738241899897560139599077166257814263354432724020387267456594044458497157226037520021564951601668256091905149808373739011153824316842260356584928931097012930709279713696588076097146536216639697002502410139891180002231258705541413293860269631209702305813614701588402302998104362562812340366960005570331931340105075488237470969553357627,
                          2,
                          13677217153160408116756482218665978246151329378802713550993307207471816940256331567699687384669466691582592352425552829806507488521715086009498475702710656178734469877407118257986414662736706529807517784982617057098081131342879985598241116865962182302248072153431236685823064649392899770528114019332463847236450731666302055534717271751161307279444324196420596233165771075662570201936819487176789243435454609296235924663430459843581194706772343053644585006691657943637200505874174079273145779265324403369833705430908627929204732075490226380388010366074406248900633161750067221657319224901070155720597206041500749236254],
                  's2k_usage': 0,
                  'mpi_private': [84637800414164198210142139900745897688922101704053610237604183449291898630805873468829881637829824002],
                  'chksum': "\x16\xf6",
                  # PublicKey methods
                  'fingerprint': "BAA202EB932697BCFCF03C9171345307625343E8",
                  'id': "71345307625343E8"}
        attrs = ['version', 'creation', 'k_asym', 'mpi', 's2k_usage',
                 'mpi_private', 'chksum']
        self.check_pgpio(values, attrs)
        self.check_PrivateSubkey(values, attrs)

    def check_PrivateSubkey(self, values, attrs):
        PublicKey._check_key_id(self, values, attrs)
        PublicKey._check_fingerprint(self, values, attrs)



#class B1_08_COMPRESSED(unittest.TestCase):
#    """Compressed packet body
#
#    - check that byte-strings work properly
#    - check that decompress() works properly
#    - check compressed body creation via compress()
#
#    :note: The test strings are only set up to test the compression algorithms,
#        *not* the viability of the decompressed strings as OpenPGP messages.
#    """
#    decomp = "testing 1, 2, 3"
#    nocomp = "\x00\x74\x65\x73\x74\x69\x6e\x67\x20\x31\x2c\x20\x32\x2c\x20\x33"
#    zip = "\x01\x2b\x49\x2d\x2e\xc9\xcc\x4b\x57\x30\xd4\x51\x30\xd2\x51\x30\x06\x00"
#    zlib = "\x02\x78\x9c\x2b\x49\x2d\x2e\xc9\xcc\x4b\x57\x30\xd4\x51\x30\xd2\x51\x30\x06\x00\x29\xd4\x04\x4d"
#
#    def setUp(self):
#        self.pkt = packet.Compressed()
#
#    def test01a_Uncompressed(self):
#        "packet.Compressed: uncompressed data"
#        self.pkt.write(self.nocomp)
#        self.assertEqual(0, self.pkt.k)
#        self.assertEqual(self.nocomp[1:], self.pkt.compressed)
#        self.assertEqual(self.decomp, self.pkt.decompress())
#    
#    def test01b_Uncompressed(self):
#        "packet.Compressed: uncompressed data (byte-fed)"
#        for c in self.nocomp:
#            self.pkt.write(c)
#        self.assertEqual(0, self.pkt.k)
#        self.assertEqual(self.nocomp[1:], self.pkt.compressed)
#        self.assertEqual(self.decomp, self.pkt.decompress())
#
#    def test01c_Uncompressed(self):
#        "packet.Compressed: create uncompressed data"
#        self.pkt.k = 0
#        self.pkt.uncompressed = self.decomp
#        self.pkt.compress()
#        self.assertEqual(0, self.pkt.k)
#        self.assertEqual(self.nocomp[1:], self.pkt.compressed)
#        self.assertEqual(self.decomp, self.pkt.decompress())
#
#    # here's a good time to write_attr(name, s)
#    def test01d_Uncompressed(self):
#        "packet.Compressed: create uncompressed data (byte-fed)"
#        self.pkt.k = 0
#        for c in self.decomp:
#            self.pkt.write_to('uncompressed', c)
#        self.pkt.compress()
#        self.assertEqual(0, self.pkt.k)
#        self.assertEqual(self.nocomp[1:], self.pkt.compressed)
#        self.assertEqual(self.decomp, self.pkt.decompress())
#
#    def test02a_Zip(self):
#        "packet.Compressed: zip-compressed data"
#        self.pkt.write(self.zip)
#        self.assertEqual(1, self.pkt.k)
#        self.assertEqual(self.zip[1:], self.pkt.compressed)
#        self.assertEqual(self.decomp, self.pkt.decompress())
#
#    def test02b_Zip(self):
#        "packet.Compressed: zip-compressed data (byte-fed)"
#        for c in self.zip:
#            self.pkt.write(c)
#        self.assertEqual(1, self.pkt.k)
#        self.assertEqual(self.zip[1:], self.pkt.compressed)
#        self.assertEqual(self.decomp, self.pkt.decompress())
#
#    def test02c_Zip(self):
#        "packet.Compressed: create zip-compressed data"
#        self.pkt.k = 1
#        self.pkt.write_to('uncompressed', self.decomp)
#        self.pkt.compress()
#        self.assertEqual(1, self.pkt.k)
#        self.assertEqual(self.zip[1:], self.pkt.compressed)
#        self.assertEqual(self.decomp, self.pkt.decompress())
#
#    def test02d_Zip(self):
#        "packet.Compressed: create zip-compressed data (byte-fed)"
#        self.pkt.k = 1
#        for c in self.decomp:
#            self.pkt.write_to('uncompressed', c)
#        self.pkt.compress()
#        self.assertEqual(1, self.pkt.k)
#        self.assertEqual(self.zip[1:], self.pkt.compressed)
#        self.assertEqual(self.decomp, self.pkt.decompress())
#
#    def test03a_Zlib(self):
#        "packet.Compressed: zlib-compressed data"
#        self.pkt.write(self.zlib)
#        self.assertEqual(2, self.pkt.k)
#        self.assertEqual(self.zlib[1:], self.pkt.compressed)
#        self.assertEqual(self.decomp, self.pkt.decompress())
#
#    def test03b_Zlib(self):
#        "packet.Compressed: zlib-compressed data (byte-fed)"
#        for c in self.zlib:
#            self.pkt.write(c)
#        self.assertEqual(2, self.pkt.k)
#        self.assertEqual(self.zlib[1:], self.pkt.compressed)
#        self.assertEqual(self.decomp, self.pkt.decompress())
#
#    def test03c_Zlib(self):
#        "packet.Compressed: create zlib-compressed data"
#        self.pkt.k = 2
#        self.pkt.write_to('uncompressed', self.decomp)
#        self.pkt.compress()
#        self.assertEqual(2, self.pkt.k)
#        self.assertEqual(self.zlib[1:], self.pkt.compressed)
#        self.assertEqual(self.decomp, self.pkt.decompress())
#
#    def test03d_Zlib(self):
#        "packet.Compressed: create zlib-compressed data (byte-fed)"
#        self.pkt.k = 2
#        for c in self.decomp:
#            self.pkt.write_to('uncompressed', c)
#        self.pkt.compress()
#        self.assertEqual(2, self.pkt.k)
#        self.assertEqual(self.zlib[1:], self.pkt.compressed)
#        self.assertEqual(self.decomp, self.pkt.decompress())


#class B1_09_SYMENCDATA(unittest.TestCase): pass
#class B1_10_MARKER(unittest.TestCase): pass


class Literal(TestPGPPacketIO):
    i_class = packet.Literal

    def test_binary(self):
        "packet.Literal: binary"
        values = {'bytes': "b\x0dcleartext.txt?\x07+kThis is some ordinary text.\n",
                  # attrs
                  'format': "b",
                  'namelen': 13,
                  'name': "cleartext.txt",
                  'modified': 1057434475,
                  'data': "This is some ordinary text.\n"}
        attrs = ['format', 'namelen', 'name', 'modified', 'data']
        skip = [self.check_leftovers, self.check_missing]
        self.check_pgpio(values, attrs, skip=skip)

    def test_text(self):
        "packet.Literal: text"
        values = {'bytes':"t\x0dcleartext.txt?\x07+kThis is some ordinary text.\r\n",
                  # attrs
                  'format':'t',
                  'namelen': 13,
                  'name':"cleartext.txt",
                  'modified':1057434475,
                  'data':'This is some ordinary text.\r\n'}

        attrs = ['format', 'namelen', 'name', 'modified', 'data']
        skip = [self.check_leftovers, self.check_missing]
        self.check_pgpio(values, attrs, skip=skip)


#class B1_12_TRUST(unittest.TestCase): pass


class UserID(TestPGPPacketIO):
    i_class = packet.UserID

    joe = 'Joeseph Schmoe (JSCMOE) <joeschmoe@mail.tld>'

    def test01(self):
        "packet.UserID: user ID"
        values = {'bytes': "Joeseph Schmoe (JSCMOE) <joeschmoe@mail.tld>",
                  # attrs
                  'uid': "Joeseph Schmoe (JSCMOE) <joeschmoe@mail.tld>"}
        attrs = ['uid']
        skip = [self.check_leftovers, self.check_missing]
        self.check_pgpio(values, attrs, skip=skip)



#class B1_17_USERATTR(unittest.TestCase):
#    "User attribute packet body - NOT IMPLEMENTED"
#    def test01(self):
#        "packet.UserAttribute: **UNTESTED**"


#class B1_18_SYMENCINTDATA(unittest.TestCase): pass
#class B1_19_MODDETECT(unittest.TestCase): pass
#
#class C_WholePackets(unittest.TestCase):
#    """Whole packet tests
#    """
#    zlib = "\x02\x78\x9c\x2b\x49\x2d\x2e\xc9\xcc\x4b\x57\x30\xd4\x51\x30\xd2\x51\x30\x06\x00\x29\xd4\x04\x4d"
#
#    #def test01(self):
#    #    "packet.MessageMill: compressed"
#    #    self.mm = packet.MessageMill()
#    #    self.mm.write(self.zlib)
#
#
#class B0_InternalPacketMechanics(unittest.TestCase):
#    """Internal packet mechanics
#
#    - incremental byte-string writes using pkt.write(str)
#    - byte-string reads using pkt.read()/pkt.read(-int)
#    - incremental byte-string reads using pkt.read(int)
#    - incomplete/unwritten attributes do not yeild packet attributes
#      (AttributeError raised)
#    - set any attribute directly
#    - manipulate any attribute
#    """
#    s1 = '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
#    s2 = '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'
#    v1 = 0
#    v2 = 1
#
#    len_s = len(s)
#    s2i = STN.str2int # and the appropriate..
#    i2s = STN.int2str # ..conversion functions
#
#    def setUp(self):
#        self.pkt = packet.TestOpenPacket(self.s2i, self.i2s)
#
#    def test01(self):
#        "packet.PacketBody: check body length, single write"
#        self.pkt.write(self.s)
#        self.assertEqual(self.len_s, self.pkt.length())
#        self.assertEqual(self.i, self.pkt.data)
#
#    def test02(self):
#        "packet.PacketBody: check body length, bytewise write"
#        for c in self.s:
#            self.pkt.write(c)
#        self.assertEqual(self.len_s, self.pkt.length())
#        self.assertEqual(self.i, self.pkt.data)
#
#    def test03(self):
#        "packet.PacketBody: check byte-string from value"
#        self.pkt.data = 0
#        self.assertEqual(self.i, self.pkt.data)
#        self.assertEqual(1, self.pkt.length()) # int2str should give 1 byte


def attrs2dict(i, attrs):
    d = {}
    for name in attrs:
        d[name] = getattr(i, name) # must have, no default
    return d


if '__main__' == __name__:
    unittest.main()
