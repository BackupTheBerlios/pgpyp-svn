from openpgp.code import *

from openpgp.sap.pkt.Packet import Tag
from openpgp.sap.pkt.Packet import Packet

import openpgp.sap.pkt.Reserved as Reserved
import openpgp.sap.pkt.PublicKeyEncryptedSessionKey as PublicKeyEncryptedSessionKey
import openpgp.sap.pkt.Signature as Signature
import openpgp.sap.pkt.OnePassSignature as OnePassSignature 
import openpgp.sap.pkt.PublicKey as PublicKey
import openpgp.sap.pkt.CompressedData as CompressedData
import openpgp.sap.pkt.LiteralData as LiteralData 
import openpgp.sap.pkt.UserID as UserID
import openpgp.sap.pkt.PublicSubkey as PublicSubkey
import openpgp.sap.pkt.SymmetricallyEncryptedIntegrityProtectedData as SymmetricallyEncryptedIntegrityProtectedData
# reserved
reserved = Reserved.Reserved()
reserved.tag = Tag()
reserved.tag.type = PKT_RESERVED
reserved.body = Reserved.ReservedBody()
# public key encrypted session key
pubseskey = PublicKeyEncryptedSessionKey.PublicKeyEncryptedSessionKey()
pubseskey.tag = Tag()
pubseskey.tag.type = PKT_PUBKEYSESKEY
pubseskey.body = PublicKeyEncryptedSessionKey.PublicKeyEncryptedSessionKeyBody()
# signature
sig = Signature.Signature()
sig.tag = Tag()
sig.tag.type = PKT_SIGNATURE
sig.body = Signature.SignatureBody()
# one-pass signature
onepass = OnePassSignature.OnePassSignature()
onepass.tag = Tag()
onepass.tag.type = PKT_ONEPASS 
onepass.body = OnePassSignature.OnePassSignatureBody()
# public key
pubkey = PublicKey.PublicKey()
pubkey.tag = Tag()
pubkey.tag.type = PKT_PUBLICKEY
pubkey.body = PublicKey.PublicKeyBody()
# compressed data
cmpr = CompressedData.CompressedData()
cmpr.tag = Tag()
cmpr.tag.type = PKT_COMPRESSED
cmpr.body = CompressedData.CompressedDataBody()
# literal data
litdat = LiteralData.LiteralData()
litdat.tag = Tag()
litdat.tag.type = PKT_LITERAL 
litdat.body = LiteralData.LiteralDataBody()
# user id
uid = UserID.UserID()
uid.tag = Tag()
uid.tag.type = PKT_USERID
uid.body = UserID.UserIDBody()
# public subkey
pubsub = PublicSubkey.PublicSubkey()
pubsub.tag = Tag()
pubsub.tag.type = PKT_PUBLICSUBKEY
pubsub.body = PublicSubkey.PublicSubkeyBody()
# symmetrically encrypted integrity protected data
symencint = SymmetricallyEncryptedIntegrityProtectedData.SymmetricallyEncryptedIntegrityProtectedData()
symencint.tag = Tag()
symencint.tag.type = PKT_SYMENCINTDATA
symencint.body = SymmetricallyEncryptedIntegrityProtectedData.SymmetricallyEncryptedIntegrityProtectedDataBody()
symencint.body.data = '' # required
