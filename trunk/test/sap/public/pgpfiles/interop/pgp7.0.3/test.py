import OpenPGP.message as MSG
import OpenPGP.util.armory as ARM

enc_d = file('encrypted_and_signed.cleartext.notepad.pgp7.0.3DHDSS1.pgp').read()
asc_d = file('key.pgp7.0.3.DHDSS1.6.0ext.pub.asc').read()


arm_list = ARM.list_armored(asc_d)

print dir(arm_list[0])

for a in arm_list:
    print arm_list[0].title
    print arm_list[0].headerlines
    pkts =  MSG.list_pkts(a.data)
    for p in pkts:
        print "got packet type: %s" % p.tag.type
    msgs =  MSG.organize_msgs(pkts)
    print msgs

