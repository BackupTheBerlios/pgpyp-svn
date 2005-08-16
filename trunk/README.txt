
Background
==========
My intent is to organize OpenPGP tools for Python. So far I've written an
implementation ('sap') which aims to be very flexible rather than bulletproof. I
wanted a tool I could use to tinker with the possibilities. The result is a
handful of simple functions representing most operations outlined in the OpenPGP
standard (draft, proposal, whatever).

If you're interested in more security-oriented OpenPGP options for Python, see
the GnuPG interface:

        http://py-gnupg.sourceforge.net/
        http://www.gnupg.org

or the cryptlib interface:

        http://trevp.net/cryptlibConverter/
        http://www.cs.auckland.ac.nz/~pgut001/cryptlib/


Acknowledgements
================
GnuPG 1.2.2 (C implementation)
    http://www.gnupg.org

    - hashing methods
    - PKCS encoding
    - CFB and 'cryption quirks

pgpmsg-1.0 source (Python packet reader)
    http://pitroda.net:8000/~jbj1
    http://pitroda.net:8000/~jbj1/pgpmsg-1.0.zip

    - index/slice packet parsing method
    - CRC, ASCII-Armoring translation, crc24()

Cryptix OpenPGP CVS (Java implementation)
    http://www.cryptix.org/
    http://www.cypherpunks.to/~cryptix/products/openpgp/

    - string-to-key madness

Crypt::OpenPGP (Perl implementation)
    http://www.stupidfool.org/perl/openpgp/

    - string-to-key madness

imc.org OpenPGP mailing list
    http://www.imc.org/ietf-openpgp/

Applied Cryptography, Second Edition by Bruce Schneier


Installation
============
To install this package, run:

    # python setup.py install

This package depends on PyCrypto (http://www.amk.ca/python/code/crypto.html)
so please install that, too.


Quick start
===========
1. Run the tests. Go into the test/sap/ directory and run ./test_public.py.
   Everything should pass.

2. Browse the source documentation or some nice, generated HTML (instructions
   on how to do this are in doc/).

3. Give the the runnable 'openpgp/sap/cmd.py' script a nice alias (I use 'sap')::

     $ alias sap="PATH/TO/cmd.py"

   ..and use it to learn more about the commandline actions and the string-based
   functions which support them::

     $ sap -h
     $ sap --explain sign
     $ sap --explain-func sign
     $ sap --explain verify
     $ sap --explain-func verify
     $ sap --explain encrypt
     $ sap --explain-func encrypt
     $ sap --explain decrypt
     $ sap --explain-func decrypt


Contact
=======
poiboy@safe-mail.net cc:poiboy@mailvault.com


TODO priority
=============
See doc/TODO.txt for a somewhat relevant TODO list.

The most important thing I want TODO is replace the packet classes in
'sap.pkt' with those in 'snap' once they are cleaned up. Once done..

    - The focus will be on the packet bodies and not the entire packet. Packet
      version, type, and length will be tacked on, meta-wise.

    - All packet components defined in the spec in terms of octets will be
      represented as instance attributes. MPI count and order will be inferred
      from algorithm codes.

    - All "manufactured" packet components (like key fingerprints) will be
      available using methods.

    - All instances will support read() and write() methods on the packet *and*
      attribute level.

Message instances (and everything above them) will be overhauled to reflect
the changes.
