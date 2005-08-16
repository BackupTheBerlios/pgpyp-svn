import os

curdir = os.path.dirname(__file__)
sepjoin = os.sep.join

def read_test_file(path_from_here):
    f = file(sepjoin([curdir]+path_from_here), 'rb')
    s = f.read()
    f.close()
    return s
