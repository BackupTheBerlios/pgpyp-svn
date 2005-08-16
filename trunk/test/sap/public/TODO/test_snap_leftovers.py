
class A2_AttributeMechanics(unittest.TestCase):
    """Attribute (StrAttr) mechanics

    The main focus is on StrAttr instances *not* holding onto both the string
    value and actual attribute value at the same time, using the conversion
    functions passed in during initialization instead.
    """
    s = 'abcdef' # arbitrary string
    i = 107075202213222 # corresponding integer value
    s2i = STN.str2int # and the appropriate..
    i2s = STN.int2str # ..conversion functions

    def setUp(self):
        self.attr = packet.StrAttr(self.s2i, self.i2s)

    def test01(self):
        "packet.StrAttr: StrAttr._str behavior"
        self.attr._str = self.s
        self.assertEqual(self.s, self.attr.str())
        self.assertEqual(self.i, self.attr.val())
        self.assertEqual(None, self.attr._val) # internal value remains unset

    def test02(self):
        "packet.StrAttr: StrAttr._val behavior"
        self.attr._val = self.i
        self.assertEqual(self.s, self.attr.str())
        self.assertEqual(self.i, self.attr.val())
        self.assertEqual('', self.attr._str) # internal string remains unset

    def test03(self):
        "packet.StrAttr: StrAttr.str() behavior"
        x = self.attr.str(self.s)
        self.assertEqual(self.s, x)
        self.assertEqual(self.s, self.attr.str())
        self.assertEqual(self.i, self.attr.val())
        self.assertEqual(self.s, self.attr._str)
        self.assertEqual(None, self.attr._val)

    def test04(self):
        "packet.StrAttr: StrAttr.val() behavior"
        x = self.attr.val(self.i)
        self.assertEqual(self.i, x)
        self.assertEqual(self.s, self.attr.str())
        self.assertEqual(self.i, self.attr.val())
        self.assertEqual(self.i, self.attr._val)
        self.assertEqual('', self.attr._str)

    def test05(self):
        "packet.StrAttr: StrAttr._str_append() behavior"
        for c in self.s:
            self.attr._str_append(c)
        self.assertEqual(self.s, self.attr.str())
        self.assertEqual(self.i, self.attr.val())
        self.assertEqual(self.s, self.attr._str)
        self.assertEqual(None, self.attr._val)

