import OpenPGP.message as MSG
d = file('encrypted_and_signed.cleartext.notepad.pgp8.0.2DHDSS1.pgp').read()
print MSG.list_msgs(MSG.list_pkts(d))

