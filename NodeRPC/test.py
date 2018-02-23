from __future__ import with_statement
import json, os, sys, getopt, hashlib, binascii, base64, time, struct, keyword, random, string, re, shutil, network, block_manager, ssl, server, cryptography, OpenSSL, psutil, datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.backends import default_backend
from globals import Globals, Patterns
from crypto import Crypto
from server import Server
from network import NetworkFieldsSize, NetworkCodes


# key_file = open('/home/rar/Desktop/Node/keys/blockmesh_node_0.key','r')
# private_key = serialization.load_pem_private_key(key_file.read(),None, default_backend())
# key_file.close()

# temp = open('txt.temp', 'wb+')
# temp.write('82495c6f5c1a4253e562fb97c55cdf39267a5ab8948f242c3083cb320c7bbb29')
# print Crypto.hash_file(temp)
# temp.close()
# os.rename('txt.temp', 'txt.blk')
# temp = open('txt.blk', 'rb')
# message = Crypto.hash_file(temp)
# temp.close()
# print message, '\n'
# print Crypto.hash(message), '\n'
# signer = private_key.signer(ec.ECDSA(hashes.SHA256()))
# signer.update(message)
# signature = signer.finalize()
# encoded_sig = base64.standard_b64encode(signature)
# print encoded_sig
# print len(signature)
# print hex
# fil = open('test.txt','w')
# fil.write('\n')
# fil.write(hex)
# def parse_configuration(configuration_file):
# 	config = {}
# 	parser = ConfigParser.ConfigParser()
# 	parser.read(configuration_file)
# 	for section in parser.sections():
# 		for option in parser.options(section):
# 			config[option] = parser.get(section, option)
# 	return config

# public_key = private_key.public_key()
# encoded_key = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
# encoded_key = '30819b301006072a8648ce3d020106052b810400230381860004013fe32b0718534a3b2446912bdf0f0e60fa32035679f0e9ec628097ed969a99bbf4bf071bec9a113e0154d23c8c7f26b6034c5426350c3e6610cd838bdd800ec9ca006b2fe794360adb40c0a8fe985329a4a61a1549685b4f86c842728a9353fe12986fe48ccf0189057e48e40dc9ff1d3b2de6200ba933827dc963b322e5c28b03cca3'
# key_bytes = binascii.unhexlify(encoded_key)
# public_key = serialization.load_der_public_key(key_bytes, default_backend())
# print binascii.hexlify(encoded_key)
# public_numbers = public_key.public_numbers()
# public_key = ec.EllipticCurvePublicNumbers(public_numbers.x, public_numbers.y, ec.SECP521R1())
# public_key = public_key.public_key(default_backend())

#retrieve verifier and feed data
# sig = base64.standard_b64decode(encoded_sig)
# verifier = public_key.verifier(sig, ec.ECDSA(hashes.SHA256()))
# verifier.update(message)
# print verifier.verify()

# sig = binascii.unhexlify('30818702411885e9f6dfcefcaa040793f82aa697c2611b1e38c34b6a958a96e04ae1c8d1efa5b261d3305360877b2cea2cb74e9feeb8e40388ebf3fd640adbbb030d4ef3d998024201cb0db008519b0d8f177691c56aba3a08af403d7bb98a13d1f68eeae8cfacfd59edc977e92178bb13b73b6e3a7a08a6ba24f31038ffdb9a071821181763c366b69c')

# encoded_sig = 'MIGHAkIBSG1kuwEeNK2kP1JZtor5ct+9BoT55Wqyhz1dj//8NxucJ3SSFxMMCFj9l0OU7OLZdAfKCB14PLrUw6SiYsPAV0ICQQjtfkMpjvdzyz0ZJEDnuMHRwdHt4Nr5dqL0p03O7zOtfh8fB3vCu+qvZzOH9cBM6zH2ohv6ZxEtqaTffaGdl51w'
# sig = base64.standard_b64decode(encoded_sig)
# verifier = public_key.verifier(sig, ec.ECDSA(hashes.SHA256()))
# verifier.update(message)
# print verifier.verify()

# config = parse_configuration('config.ini')
# config['nodes'] = json.loads(config['nodes'])
# print config['nodes'][0]['host']
# header = {}
# header['IDENTIFICATION'] = []
# header['NETWORK'] = []
# header['RESOURCES'] = []
# header['IDENTIFICATION'].append("be7336c2d3959231d4da5f2e7f7b6f109babaf923f4d695cb6b7827c02f4d6bb")
# header['IDENTIFICATION'].append("f980e79f6ac6d01e34a341f74fc088aa9e72b02ebee6a9fef39039390c1057be")
# header['RESOURCES'].append("eea1933c2e36cb5d27fc033c9ced89affdf0404bbb20e0ec78112825a0e9b5d0")
# header['RESOURCES'].append("15d4319965f0ed04eb860bd94752104c7874ce8d78f8623c6441e76ad03164a4")
# header['RESOURCES'].append("ed7a0ee29f6701b22e216ddbe312d15db79e30e24a5123e0961ed3e2f0f540b2")
# header['NETWORK'].append("469402432173bb22428167c0eeb14040877aa576153406485f122a702d284d92")

# previousBlockHash = "0000000000000000000000000000000000000000000000000000000000000000"

# print Crypto.hash('{"previousBlockHash":"'+previousBlockHash+'","header":'+json.dumps(header, sort_keys=True)+'}')
# key_bytes = binascii.unhexlify(encoded_key)
# public_key = serialization.load_der_public_key(key_bytes, default_backend())
# verifier = public_key.verifier(signature, ec.ECDSA(hashes.SHA256()))
# verifier.update(message)
# print verifier.verify()

# message = '{"resource":"NETWORK","entity":"BLOCKMESHCONTROLLER0","data":["a",1,"b",2],"signature":"MIGIAkIBT1SbGQU2MVXXRnIGmgXqFqctmawXe3ryRxkw39IUilFaPMLQJ5wWiuO+1L2d6TIPodmjnlwxmDvwgFvFQUS4ybECQgDwMkmQgxDxOyGuJGan8jEytxSoiEeevEOn0JFFNijfWwr65IUGYiGZLHH+WgNhI+4CoTekuW67j2q3+iinKUZ5sQ=="}'
# message = json.loads(message)
# print type(message['data'])

# worker = '0'
# hash = '546190422a59c7ef2f0f00f81fda5fd016ba95b8768f7772e4948b2145d03bf5'
# signature = 'MIGHAkFA2dKHF5vBkBGyo9gWZscBOj/9kBk3PfnsY4MUC8AyfWwpV3CI5687h0TgbunBOKZeZSnDMStftRozYKFSvtva/AJCAILeUDSfPY7Da5pf4zRk74Nwr/ZWgbcdTFWiIe/iD8rHtR7PbTiVvAwFkWEr8+quJDDQcWaj9GrAhaOVRP4q97xx'

# print Patterns.validate(Patterns.WORKER, worker)
# print Patterns.validate(Patterns.HASH, hash)
# print Patterns.validate(Patterns.SIGNATURE, signature)

msg = 'hjhk'
print msg == True
print msg == False
print msg == None
msg = None
print msg == True
print msg == False
print msg == None
msg = False
print msg == True
print msg == False
print msg == None