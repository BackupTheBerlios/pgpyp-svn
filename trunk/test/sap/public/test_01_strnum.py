"String and number conversions"

import unittest

# test targets
from openpgp.sap.util.strnum import str2int
from openpgp.sap.util.strnum import int2str
from openpgp.sap.util.strnum import int2quadoct
from openpgp.sap.util.strnum import int2partial
from openpgp.sap.util.strnum import partial2int
from openpgp.sap.util.strnum import int2doubleoct
from openpgp.sap.util.strnum import doubleoct2int
from openpgp.sap.util.strnum import str2hex
from openpgp.sap.util.strnum import hex2str

# package help
from openpgp.sap.list import list_pkts

# test help
from support import read_test_file


class A0S2N(unittest.TestCase):
    good_strings = [('\x00', 0),
                    ('\xac\x13\x0d', 11277069),
                    ('\xff\xff\xff\xff', 4294967295),
                    ('\xff\xff\xff\xff\xff\xff\xfd\x0a\xac\x34\xbb\x92\xb5\xac\x13\x0d', 340282366920938449493151348672028218125L)]
    bad_types = [None, 1, {0:'a'}]

    def testB0BadTypesS2N(self):
        "strnum: str2int bad types"
        for b in self.bad_types:
            try:
                str2int(b)
            except: # make sure any old exception is raised
                pass
            else:
                raise

    def testC0TranslationS2N(self):
        """strnum: str2int output"""
        for v in self.good_strings:
            self.assertEqual(v[1], str2int(v[0]))


class A2N2Q(unittest.TestCase):
    good_nums = [(0, '\x00\x00\x00\x00'),
                 (255, '\x00\x00\x00\xff'),
                 (256, '\x00\x00\x01\x00'),
                 (4294967295, '\xff\xff\xff\xff')]
    bad_types = [None, 'a', {0:1}, [200]]
    invalid_nums = [4294967296]

    def testB2InvalidNums(self):
        """strnum: int2quadoct invalid integer values (ValueError)"""
        for i in self.invalid_nums + self.bad_types:
            self.assertRaises(ValueError, int2quadoct, i)

    def testC0TranslationN2Q(self):
        """strnum: int2quadoct output"""
        for v in self.good_nums:
            self.assertEqual(v[1], int2quadoct(v[0]))

    def testC4Inversion(self):
        """strnum: number to string inversion (int2quadoct/str2int())"""
        for o in self.good_nums:
            self.assertEqual(o[0], str2int(int2quadoct(o[0])))


class A3Partials(unittest.TestCase):
    good_partials = [(1, '\xe0'),
                     (16384, '\xee'),
                     (8388608,'\xf7'),
                     (1073741824,'\xfe')]
    bad_types = [None, 'a', {0:1}, [200]]
    invalid_nums = [7, 1000000003]

    def testB2InvalidNums(self):
        """strnum: int2partial invalid integer values (ValueError)"""
        for i in self.invalid_nums + self.bad_types:
            self.assertRaises(ValueError, int2partial, i)

    def testB4NumTranslation(self):
        """strnum: int2partial output"""
        for p in self.good_partials:
            self.assertEqual(p[1], int2partial(p[0]))

    def testC4Inversion(self):
        """strnum: number to partial inversion (int2partial/partial2int)"""
        for p in self.good_partials:
            self.assertEqual(p[0], partial2int(int2partial(p[0])))


class A4DoubleOcts(unittest.TestCase):
    good_double_octs = [(192, '\xc0\x00'),
                        (400, '\xc0\xd0'),
                        (3245,'\xcb\xed'),
                        (6180, '\xd7\x64'),
                        (8383, '\xdf\xff')]

    # int2doubleoct()
    def testB0BadTypesI2D(self):
        """strnum: int2doubleoct bad types (TypeError)"""
        for b in [None, 'a', {0:1}, [200]]:
            self.assertRaises(TypeError, int2doubleoct, b)

    def testB4IntTranslation(self):
        """strnum: int2doubleoct output"""
        for v in self.good_double_octs:
            self.assertEqual(v[1], int2doubleoct(v[0]))

    # doubleoct2int()
    def testC0BadTypesD2I(self):
        """strnum: doubleoct2int bad types (TypeError)"""
        for b in [None, {0:1}, [200]]:
            self.assertRaises(TypeError, doubleoct2int, b)
            
    def testC6OctTranslation(self):
        """strnum: doubleoct2int output"""
        for v in self.good_double_octs:
            self.assertEqual(v[0], doubleoct2int(v[1]))

    # both
    def testD2Sanity(self):
        """strnum: double octet inversion (int2doubleoct/doubleoct2int)"""
        for o in self.good_double_octs:
            self.assertEqual(o[0], doubleoct2int(int2doubleoct(o[0])))


# don't know why these are separated out
# oh well, at least they're using real values
class A5FunkyStuff(unittest.TestCase):
    """
    """
    def __init__(self, *a, **kw):
        unittest.TestCase.__init__(self, *a, **kw)
        key_d = read_test_file(['pgpfiles','key','DSAELG1.pub.gpg'])
        self.key = list_pkts(key_d)[0]

    def test01_int2str_str2int(self):
        "strnum: string/integer inversion (int2str/str2int)"
        body = self.key.body
        for i in [body.DSA_p.value, body.DSA_q.value, body.DSA_g.value, body.DSA_y.value]:
            self.assertEqual(i, str2int(int2str(i)))

    def test02_str2hex_hex2str(self):
        "strnum: string/hex inversion (str2hex/hex2str)"
        fprint = self.key.body.fingerprint
        xprint = str2hex(hex2str(fprint))
        self.assertEqual(fprint, xprint)


if '__main__' == __name__:
    unittest.main()
