#!/usr/bin/env python

import unittest
import os.path

test_dir = 'public'
prefix = 'test_'

def get_testmods():
    suite_dir = os.sep.join([os.path.dirname(__file__), test_dir])
    suite_files = os.listdir(suite_dir)

    has_prefix = lambda s: 0 == s.find(prefix)
    get_modname = lambda s: s.split('.', 1)[0]

    testnames = filter(has_prefix, suite_files)
    testnames = map(get_modname, testnames)

    modnames = []
    # eliminate duplicates (like from test_x.py and test_x.pyc)
    for testname in testnames:

        if testname not in modnames:
            modnames.append(testname)

    modnames.sort() 
    modnames = ["%s.%s" % (test_dir, n) for n in modnames]

    mods = map(lambda m: __import__(m, None, None, [m]), modnames)

    return mods

def suite():
    alltests = unittest.TestSuite()

    for mod in get_testmods():
        alltests.addTest(unittest.findTestCases(mod))
    
    return alltests

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
