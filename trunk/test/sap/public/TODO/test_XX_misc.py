import unittest


class PacketDisplay(unittest.TestCase):
    """
    """
    def testG01show_packets(self):
        "sap.sap: show_packets() DSA secret key, no pass"
        d = file(join(['pgpfiles','key','DSAELG1.sec.nopass.gpg'])).read()
        packet_display = SAP.show_packets(d)
        ### uncomment to reset pickled output/recomment before testing
        f = file(join(['pickles','report_packet_seckey1.py']), 'w')
        pickle.dump(packet_display, f)
        f.close()
        ###
        pickle_display = pickle.load(file(join(['pickles','report_packet_seckey1.py'])))
        self.assertEqual(packet_display, pickle_display)

class KeyTargets(unittest.TestCase):
    """
    """
    def testK01ParseKeyTargets(self):
        "list: parse_keyids()"
        # repetition should be ignored
        s = " 9F6C5AAB67B39A06 ,,9F6C5AAB67B39A06,, Yoyoman,, 9CFBB7E5AE12E579::Yoyoman "
        s += ",, ::Mango,, 9CFBB7E5AE12E579::" # normal uid, primary tuple
        t = parse_keyids(s)
        self.assertEqual(5, len(t))
        self.assertEqual(t[0], '9F6C5AAB67B39A06')
        self.assertEqual(t[1], 'Yoyoman')
        self.assertEqual(t[2], ('9CFBB7E5AE12E579', 'Yoyoman'))
        self.assertEqual(t[3], 'Mango')
        self.assertEqual(t[4], ('9CFBB7E5AE12E579', None))

    def testK02a_find_keys_1(self):
        ""
        key_d = read_test_file(['pgpfiles','key','DSAELG_1_and_3.pub.asc'])
        mode = 'sign'
        keymsg1, keymsg2 = list_as_signed(key_d)

    def xxxtestK02GetKeyTargetsSign(self):
        "sap.list: list_keyids()/find_keys() 'sign'"
        key_d = read_test_file(['pgpfiles','key','DSAELG_1_and_3.pub.asc'])
        mode = 'sign'
        searches = ["0CFC2B6DCC079DF3,, 1760A8DE7441604A",
                    #"::Tester,, DIFFHELL",
                    #"0CFC2B6DCC079DF3::Tester,, 1760A8DE7441604A::DIFFHELL",
                    "0CFC2B6DCC079DF3::,, 1760A8DE7441604A::"]
        keymsg1, keymsg2 = list_as_signed(key_d)
        for s in searches:
            print 
            print "list_keyids"
            print 
            i = list_keyids(s)
            print i
            print find_keys([keymsg1, keymsg2], keyids=i, mode=mode)
            keyt1, keyt2 = find_keys([keymsg1, keymsg2], keyids=i, mode=mode)
            # make sure that both keys are found
            self.assertEqual(keyt1[0].rawstr(), keymsg1.rawstr())
            self.assertEqual(keyt2[0].rawstr(), keymsg2.rawstr())
            # make sure that their signing key IDs were reported
            #self.assertEqual(keyt1[1][0], keymsg1.primary_id)
            #self.assertEqual(keyt2[1][0], keymsg2.primary_id)
            self.assertEqual(keyt1[1][0], keymsg1.primary_fprint)
            self.assertEqual(keyt2[1][0], keymsg2.primary_fprint)
            # make sure that only one signing ID was reported per key
            print keyt1
            print keyt2
            self.assertEqual(len(keyt1[1]), 1)
            self.assertEqual(len(keyt2[1]), 1)


    def testK03GetKeyTargetsEncrypt(self):
        "sap.list: parse_keyids()/list_key_targets() 'encrypt'"
        key_d = read_test_file(['pgpfiles','key','DSAELG_1_and_3.pub.asc'])
        mode = 'encrypt'
        searches = ["::Tester,, DIFFHELL",
                    "0CFC2B6DCC079DF3::Tester,, 1760A8DE7441604A::DIFFHELL",
                    "0CFC2B6DCC079DF3::CB7D6980A1F2BEF6,, 1760A8DE7441604A::71345307625343E8"]
        keymsg1, keymsg2 = list_as_signed(key_d)
        for s in searches:
            ids = parse_keyids(s)
            keytargs1, keytargs2 = list_key_targets(key_d, ids, mode)
            # make sure that both keys are found
            self.assertEqual(keytargs1[0].rawstr(), keymsg1.rawstr())
            self.assertEqual(keytargs2[0].rawstr(), keymsg2.rawstr())
            # make sure that their encrypting key IDs were reported
            self.assertEqual(keytargs1[1][0], keymsg1._b_subkeys[0].leader.body.id)
            self.assertEqual(keytargs2[1][0], keymsg2._b_subkeys[0].leader.body.id)
            # make sure that only one encrypting key ID was reported
            self.assertEqual(len(keytargs1[1]), 1)
            self.assertEqual(len(keytargs2[1]), 1)

    # this "feature" may die hard
    def testK04GetKeyTargetsForceWrongKey(self):
        "sap.list: parse_keyids()/list_key_targets() specifying keys regardless of mode"
        key_d = read_test_file(['pgpfiles','key','DSAELG_1_and_3.pub.asc'])
        mode = 'encrypt'
        # these searches just force the signing key retrieval instead of encrypting key
        searches = ["0CFC2B6DCC079DF3::,, 1760A8DE7441604A::",
                    "0CFC2B6DCC079DF3,, 1760A8DE7441604A"]
        keymsg1, keymsg2 = list_as_signed(key_d)
        for s in searches:
            ids = parse_keyids(s)
            keytargs1, keytargs2 = list_key_targets(key_d, ids, mode)
            # make sure that both keys are found
            self.assertEqual(keytargs1[0].rawstr(), keymsg1.rawstr())
            self.assertEqual(keytargs2[0].rawstr(), keymsg2.rawstr())
            # make sure that their SIGNING key IDs (though not appropriate) were reported
            self.assertEqual(keytargs1[1][0], keymsg1.primary_id)
            self.assertEqual(keytargs2[1][0], keymsg2.primary_id)
            # make sure that only one encrypting key ID was reported
            self.assertEqual(len(keytargs1[1]), 1)
            self.assertEqual(len(keytargs2[1]), 1)
        # then check that both the signing key AND encrypting key (via user ID) can be had
        s = "::Tester,, DIFFHELL,, 0CFC2B6DCC079DF3,, 1760A8DE7441604A"
        ids = parse_keyids(s)
        keytargs1, keytargs2 = list_key_targets(key_d, ids, mode)
        # basic message check
        self.assertEqual(keytargs1[0].rawstr(), keymsg1.rawstr())
        self.assertEqual(keytargs2[0].rawstr(), keymsg2.rawstr())
        # given the order of the targets in the string, expect encrypting targets first
        keymsg1_enckey = keymsg1._b_subkeys[0].leader.body.id
        keymsg2_enckey = keymsg2._b_subkeys[0].leader.body.id
        self.assertEqual(keytargs1[1], [keymsg1_enckey, keymsg1.primary_id])
        self.assertEqual(keytargs2[1], [keymsg2_enckey, keymsg2.primary_id])

class Stuff2LiteralFiles(unittest.TestCase):
    """
    """
    def testD01SingleFile2LiteralMsg(self):
        "list: targets2literalmsg() construct literal data list"
        f1 = sepjoin([curdir,'pgpfiles','cleartext.txt'])
        f1_file = file(f1, 'rb')
        f1_name = os.path.basename(f1)
        f1_d = file(f1).read()
        f1_modified = os.path.getmtime(f1)

        f2 = sepjoin([curdir,'pgpfiles','key','DSAELG1.pub.gpg'])
        f2_file = file(f2, 'rb')
        f2_name = os.path.basename(f2)
        f2_d = file(f2).read()
        f2_modified = os.path.getmtime(f2)

        f3 = sepjoin([curdir,'pgpfiles','enc','sap.DSAELG1.zip.gpg'])
        f3_file = file(f3, 'rb')
        f3_name = os.path.basename(f3)
        f3_d = file(f3).read()
        f3_modified = os.path.getmtime(f3)
    
        litmsg = targets2literalmsg([f1_file, f2_file, f3_file])

        self.assertEqual(f1_name, litmsg.literals[0].body.filename)
        self.assertEqual(f1_d, litmsg.literals[0].body.data)
        self.assertEqual(f1_modified, litmsg.literals[0].body.modified)

        self.assertEqual(f2_name, litmsg.literals[1].body.filename)
        self.assertEqual(f2_d, litmsg.literals[1].body.data)
        self.assertEqual(f2_modified, litmsg.literals[1].body.modified)

        self.assertEqual(f3_name, litmsg.literals[2].body.filename)
        self.assertEqual(f3_d, litmsg.literals[2].body.data)
        self.assertEqual(f3_modified, litmsg.literals[2].body.modified)

    def testD02SingleFile2LiteralMsg(self):
        "list: files2literals() using empty list (catch PGPError)"
        self.assertRaises(Exception, targets2literalmsg, [])


if '__main__' == __name__:
    unittest.main()
