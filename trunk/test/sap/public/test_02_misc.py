"""Test Miscellaneous Functions"""

import unittest

# test targets
from openpgp.sap.util.misc import unique_order
from openpgp.sap.util.misc import order_intersection
from openpgp.sap.util.misc import intersect_order

# test help
from support import read_test_file

class ReallyMiscellaneousStuff(unittest.TestCase):
    
    def testA01unique_order(self):
        """misc: unique_order() forward"""
        # simple
        l = [1, 1, 2, 2, 3, 3, 4, 4]
        new_l = unique_order(l)
        self.assertEqual(new_l, [1, 2, 3, 4])
        # a little harder
        l = [1, 2, 1, 2, 2, 3, 1, 3, 4, 3, 4, 2, 4]
        new_l = unique_order(l)
        self.assertEqual(new_l, [1, 2, 3, 4])

    def testA02unique_order(self):
        """misc: unique_order() reverse"""
        # a little harder still
        l = [1, 2, 1, 2, 2, 3, 1, 3, 4, 3, 4, 2, 4]
        new_l = unique_order(l, True)
        self.assertEqual(new_l, [1, 3, 2, 4])

    # This is to illustrate what's going on.
    def testA03order_intersection(self):
        """misc: order_intersection()"""
        a = [1, 2, 3, 4]
        b = [3, 4, 5, 6]
        c = [3, 4, 4, 5]
        ll = [a, b, c]
        tl = order_intersection(ll)
        self.assertEqual(tl, [4, 3])
    # It's just a code quirk that 1, 10, 3 appear in this order since
    # they share the same frequency. This test is just to alert changes
    # in the function source.
    def testA04order_intersection(self):
        """misc: order_intersection() alert source change"""
        a = [1, 2, 3, 4, 5, 10]
        b = [1, 3, 4, 5, 6, 10]
        c = [1, 3, 4, 5, 4, 5, 5, 10, None]
        ll = [a, b, c]
        tl = order_intersection(ll)
        self.assertEqual(tl, [5, 4, 1, 10, 3])

    def testA05intersect_order(self):
        """misc: intersect_order()"""
        a = [1, 2, 3, 4, 5, 10]
        b = [1, 3, 4, 5, 6, 10]
        c = [1, 3, 4, 5, 4, 5, 5, 10, None]
        ll = [a, b, c]
        tl = intersect_order(ll)
        self.assertEqual(tl, [1, 3, 4, 5, 10])


if '__main__' == __name__:
    unittest.main()
