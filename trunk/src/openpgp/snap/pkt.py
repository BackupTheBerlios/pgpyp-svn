
from openpgp.code import *

from openpgp.sap.util.strnum import int2str, str2int, sigbits, mpilen2int, str2hex

PGIO_STR_TYPE = 'str'
PGIO_MPI_TYPE = 'mpi'
PGIO_S2K_TYPE = 's2k'
LEN_UNDEFINED = 'undefined'

class PGPktIO:
    """
    """
    def __init__(self):
        """
        Define self._attrs as a list of tuples in the order they appear in a
        native string. The tuples contain 5 items:

            - name: str instance attribute name
            - type: str attribute type
            - amount: amount (int) of type required for completion or None if
              undefined/unlimited amount
            - conversion: tuple of functions (string->value, value->string)
            - applicability: function called to determine attribute applicability
        """
    
    def __eq__(self, other):
        "Two PGPPacketIO instances are equal if both sets of '_attrs' match."
        for attr in self._attrs: # check only spec-specific names
            name = attr[0]

            if hasattr(self, name): # the other must match

                if hasattr(other, name):

                    if getattr(other, name) != getattr(self, name):
                        return False

                else:
                    return False

            elif hasattr(other, name): # self is missing something
                return False

        return True

    def _ne__(self, other):
        return not self.__eq__(self, other)

    def awol(self):
        """Return first missing attribute or None.
        """
        # The reason this only tries to return the first missing attr is because
        # you can't get a "complete" list when version/etc. dependencies
        # determine following attrs.
        for attr in self._attrs:
            name = attr[0]
            apply_attr = attr[-1]

            if callable(apply_attr):
                apply_attr = apply_attr()

            if apply_attr and not hasattr(self, name):
                return name

    # later support read(self_attr_name)
    def read(self):
        """
        Right now, this just goes through the attribute names in order. if a gap
        exists, it'll just cat the strings for the values on either side of the
        gap.
        """
        strlist = []

        for name, _type, amount, converters, apply_attr in self._attrs:
            val2str = converters[1]

            if hasattr(self, name):

                if callable(amount):
                    amount = amount()

                strlist.append(val2str(getattr(self, name), amount))

        return ''.join(strlist)

    def write(self, s):
        """
        """
        leftover = ''
        INCOMPLETE, COMPLETE = 0, 1
        # start w/ COMPLETE since cannot determine completeness on an attribute
        # by attribute basis, while incomplete attributes speak for themselves
        state = COMPLETE

        if not hasattr(self, '_wbuf'):
            self._wbuf = s
        else:
            self._wbuf = ''.join([self._wbuf, s])

        for name, _type, amount, converters, apply_attr in self._attrs:
            #print "handling name", name
            str2val = converters[0] # only need string->value converter

            if callable(apply_attr):
                apply_attr = apply_attr()

            if not apply_attr:
                continue # not applicable, move on to the next attribute

            if callable(amount):
                amount = amount()

            if LEN_UNDEFINED == amount:

                if PGIO_STR_TYPE == _type:

                    if hasattr(self, name):
                        s = ''.join([getattr(self, name), self._wbuf])
                        setattr(self, name, s)
                    else:
                        setattr(self, name, self._wbuf)

                    self._wbuf = '' # gets all used up
                    break

                else:
                    raise Exception("Can't handle undefined type: %s" % _type) 

            if not hasattr(self, name): # attribute is not set yet..

                if PGIO_STR_TYPE == _type:

                    if amount <= len(self._wbuf):
                        bufslice = self._wbuf[:amount]
                        self._wbuf = self._wbuf[amount:]
                        setattr(self, name, str2val(bufslice, amount))

                    else:
                        state = INCOMPLETE
                        break

                # MPI/S2K may be a little too consuming for byte-wise-ish writes
                # ..and they also ignore the str2val stuff, and just use the
                # appropriate function directly. This is fine so long as write()
                # is a general thing, but if we allow individual attr writes this
                # will have to change. In any case, the whole str/val tuple
                # beauteousness must be reconsidered.
                elif PGIO_MPI_TYPE == _type:
                    mpi_list, idx = str2mpi(self._wbuf, amount)

                    if len(mpi_list) == amount:
                        self._wbuf = self._wbuf[idx:]
                        setattr(self, name, mpi_list)
                    else:
                        state = INCOMPLETE
                        break

                # ..and all that above applies to the silly s2k 'amount'.
                elif PGIO_S2K_TYPE == _type:
                    s2k_list, idx = str2s2k(self._wbuf, amount)

                    if len(s2k_list) == amount:
                        self._wbuf = self._wbuf[idx:]
                        setattr(self, name, s2k_list[0]) # ..silly..
                    else:
                        state = INCOMPLETE
                        break

        if COMPLETE == state:
            leftover = self._wbuf
            self._wbuf = ''

        return leftover


class Literal(PGPktIO):
    """
    """
    def __init__(self):
        len_format = 1
        len_namelen = 1
        len_name = self._get_namelen
        len_modified = 4

        self._attrs = [('format', PGIO_STR_TYPE, len_format, svt_str(), True),
                       ('namelen', PGIO_STR_TYPE, len_namelen, svt_int(), True),
                       ('name', PGIO_STR_TYPE, len_name, svt_str(), True),
                       ('modified', PGIO_STR_TYPE, len_modified, svt_int(), True),
                       ('data', PGIO_STR_TYPE, LEN_UNDEFINED, svt_str(), True)]

    def _get_namelen(self):
        return self.namelen


class PublicKey(PGPktIO):
    """
    """
    mpimap = {2:[ASYM_RSA_S, ASYM_RSA_EOS, ASYM_RSA_E],
              4:[ASYM_DSA],
              3:[ASYM_ELGAMAL_EOS, ASYM_ELGAMAL_E]}

    def __init__(self):
        len_version = 1
        len_created = 4
        len_v3_expires = 2
        len_k_asym = 1
        len_mpi = self._len_mpi
        apply_v3 = self._apply_v3

        self._attrs = [
            ('version', PGIO_STR_TYPE, len_version, svt_int(), True),
            ('created', PGIO_STR_TYPE, len_created, svt_int(), True),
            ('v3_expires', PGIO_STR_TYPE, len_v3_expires, svt_int(), apply_v3),
            ('k_asym', PGIO_STR_TYPE, len_k_asym, svt_int(), True),
            ('mpi', PGIO_MPI_TYPE, len_mpi, svt_mpi(), True)]

    def get_fprint(self):
        """Get a key's fingerprint as an uppercase hex string.
        """
        if 3 == self.version:
            import md5

            n_bytes = mpi2str([self.mpi[0]], None)[2:] # chop off MPI length bytes
            e_bytes = mpi2str([self.mpi[1]], None)[2:]

            return md5.new(''.join([n_bytes, e_bytes])).hexdigest().upper()

        elif 4 == self.version:
            import sha
            f_data = ''.join([int2str(self.version), #self._val2str('version'),
                              int2str(self.created), #self._val2str('created'),
                              int2str(self.k_asym), #self._val2str('k_asym'),
                              mpi2str(self.mpi, None)]) #self._val2str('mpi')])
            len_f_data = len(f_data)
            hi = chr((0xffff & len_f_data) >> 8) # high order packet length
            lo = chr(0xff & len_f_data) # low order packet length

            f = ['\x99', hi, lo, f_data]
            return sha.new(''.join(f)).hexdigest().upper()

    def get_id(self):
        """Get a key's public ID as an uppercase hex string.
        """
        if 3 == self.version: # only use first "RSA n" MPI
            return str2hex(mpi2str([self.mpi[0]], None)[-8:])

        elif 4 == self.version:
            return self.get_fprint()[-16:]

    def _len_mpi(self):
        for k, v in self.mpimap.items():
            if self.k_asym in v:
                return k

    def _apply_v3(self):
        if self.version < 4:
            return True

        return False


class PublicSubkey(PublicKey):
    """
    """
    def __init__(self):
        PublicKey.__init__(self)


class PrivateKey(PublicKey):
    """
    """
    private_mpimap = {4:[ASYM_RSA_S, ASYM_RSA_EOS, ASYM_RSA_E],
                      1:[ASYM_DSA, ASYM_ELGAMAL_EOS, ASYM_ELGAMAL_E]}
    ivmap = {8:[SYM_IDEA, SYM_DES3, SYM_CAST5, SYM_BLOWFISH],
             16:[SYM_AES128, SYM_AES192, SYM_AES256, SYM_TWOFISH]}

    def __init__(self):
        PublicKey.__init__(self)

        len_s2k_usage = 1
        len_k_sym = self._len_k_sym
        len_s2k = 1
        len_iv = self._len_iv
        len_mpi_prv = self._len_mpi_private
        len_mpi_enc = LEN_UNDEFINED
        len_csum = 2

        apply_s2k = self._apply_s2k
        crypted = self._crypted
        clear = lambda: not crypted()

        add = self._attrs.append
        add(('s2k_usage', PGIO_STR_TYPE, len_s2k_usage, svt_int(), True))
        add(('k_sym', PGIO_STR_TYPE, len_k_sym, svt_int(), True))
        add(('s2k', PGIO_S2K_TYPE, len_s2k, svt_s2k(), apply_s2k))
        add(('iv', PGIO_STR_TYPE, len_iv, svt_str(), crypted))
        add(('mpi_encrypted', PGIO_STR_TYPE, len_mpi_enc, svt_str(), crypted))
        add(('mpi_private', PGIO_MPI_TYPE, len_mpi_prv, svt_mpi(), clear))
        add(('csum', PGIO_STR_TYPE, len_csum, svt_str(), clear))

    def _apply_s2k(self):
        if self.s2k_usage in [254, 255]:
            return True

        return False

    def _crypted(self):
        if 0 == self.k_sym:
            return False
        return True

    def _len_k_sym(self):
        if self.s2k_usage in [254, 255]:
            return 1

        self.k_sym = self.s2k_usage
        return 0

    def _len_mpi_private(self):
        k_asym = self.k_asym

        for k, v in self.private_mpimap.items():
            if k_asym in v:
                return k

    def _len_iv(self):
        k_sym = self.k_sym

        for k, v in self.ivmap.items():
            if k_sym in v:
                return k


class PrivateSubkey(PrivateKey):
    """
    """
    def __init__(self):
        PrivateKey.__init__(self)


class UserID(PGPktIO):
    """
    """
    def __init__(self):
        self._attrs = [('uid', PGIO_STR_TYPE, LEN_UNDEFINED, svt_str(), True)]


class S2K(PGPktIO):
    """
    """
    def __init__(self):
        len_spec = 1
        len_k_hash = 1
        len_salt = 8
        len_count = 1

        apply_salt = lambda: 1 <= self.spec
        apply_count = lambda: 3 <= self.spec

        self._attrs = [
            ('spec', PGIO_STR_TYPE, len_spec, svt_int(), True),
            ('k_hash', PGIO_STR_TYPE, len_k_hash, svt_int(), True),
            ('salt', PGIO_STR_TYPE, len_salt, svt_str(), apply_salt),
            ('count_code', PGIO_STR_TYPE, len_count, svt_int(), apply_count)]

    def get_count(self):
        """Translate count code to the number of octets hashed into the key.

        :Returns: octet hash count (see RFC 2440 3.7.1.3)
        """
        c = self.count_code
        return (16 + (c & 15)) << ((c >> 4) + 6)

# svt_*() functions return (string_to_value, value_to_string) functions which
# all accept (string, length) or (value, length) paramters where 'length' is the
# length of either the string to get a value from or the length of the string
# created from the value.

def svt_int():
    str2val = lambda string, limit: str2int(string[:limit])
    val2str = lambda value, limit: _limit_int2str(value, limit)
    return str2val, val2str

def svt_mpi():
    str2val = lambda string, limit: str2mpi(string, limit)[0] # [0] mpi list only
    return str2val, mpi2str

def svt_str():
    return str2str, str2str

def svt_s2k():
    val2str = lambda value, limit: value.read() # S2K instance already, so read()
    return str2s2k, val2str
    
def str2s2k(s, limit=None): # dummy limit, return only one s2k
    i = S2K()
    l = i.write(s)

    if not i.awol():
        idx = len(s) - len(l)
        return [i], idx

    return [], 0

def _limit_int2str(i, limit):
    "Ensure that int2str output has enough ('limit') bytes."
    s = int2str(i)[:limit]
    len_s = len(s)

    if len_s < limit:
        s = ((limit - len_s) * '\x00') + s

    return s

def str2str(s, limit):
    """
    """
    if LEN_UNDEFINED == limit:
        return str(s)

    return str(s)[:limit]

def str2mpi(s, limit):
    """Convert a MPI byte-string into an integer.

    :Parameters:
        - `s`: MPI string
        - `limit`: *optional* maximum number of MPIs to search for

    :Returns: list of MPI values (integers/longs)
    """
    import struct

    idx = 0
    mpi_list = []

    while True:
 
        if limit and limit == len(mpi_list):
            break

        mpilen_d, idx = read_slice(s, 2, idx)

        if 2 == len(mpilen_d):
            # we don't care about bit length, just the bytes containing them
            mpilen = mpilen2int(mpilen_d)
            int_d, idx = read_slice(s, mpilen, idx)
            len_int_d = len(int_d)

            if len_int_d == mpilen:
                i = struct.unpack('>'+str(len_int_d)+'s', int_d)[0]
                mpival = str2int(i) 
                mpi_list.append(mpival)

                continue # if good, keep going

        break # otherwise quit

    return mpi_list, idx

def mpi2str(l, limit):
    """Convert a list of MPIs to a byte-string.

    :Parameters:
        - `l`: list of MPI integers
        - `limit`: dummy parameter to follow svt_*() suit

    :Returns: MPI byte-string

    :note: This should probably return some sort of an index like `str2mpi()`
        since a limit < len(l) might be useful. But it's not useful now.
    """
    d = []

    for i in l:
        i_d = int2str(i)
        i_length = len(i_d)
        bit_count = sigbits(i_d[0]) + (8 * (i_length - 1))
        i_length_str = int2str(bit_count)

        if 2 < len(i_length_str):
            raise ValueError, "MPI integer > two octs: %s octets used>" % str(i_length)

        elif 1 == len(i_length_str):
            i_length_str = ''.join(['\x00', i_length_str])

        d.append(''.join([i_length_str, i_d])) # since limit checks complete mpi

        if limit == len(d):
            break

    return ''.join(d)

def read_slice(s, n, i):
    """Slice a string and get an incremented index.

    :Parameters:
        - `s`: string to read slice from
        - `n`: length of slice
        - `i`: start slice index 

    :Returns: slice, updated index

    :note: The updated index will not equal `i` + `n` if it is larger than
        string `s` will support.
    """
    new_i = i+n
    slice = s[i:new_i]

    return slice, i+len(slice)

