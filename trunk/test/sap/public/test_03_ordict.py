"Ordered dictionary tests"

import unittest

# test target
from openpgp.sap.util.ordict import ordict

class A00DictionaryTests(unittest.TestCase):
    """
    """
    def testA01(self):
        "util.ordict: __setitem__/__getitem__"
        d = ordict()
        d['a'] = 23
        self.assertEqual(23, d['a'])

    def testA02(self):
        "util.ordict: index access == keyword access"
        d = ordict()
        d['a'] = 22
        self.assertEqual(d['a'], d[0])

    def testA03(self):
        "util.ordict: __delitem__ via index"
        d = ordict()
        d['a'] = 22
        d['b'] = 33
        del d[0]
        self.assertEqual(d.list(), [33])

if '__main__' == __name__:
    unittest.main()
