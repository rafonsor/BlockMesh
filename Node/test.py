import json, os, sys, getopt, hashlib, binascii, base64, time, struct, keyword, random, string, re, shutil, network, block_manager, ssl, server, cryptography, OpenSSL, psutil
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.backends import default_backend
from globals import Globals, Patterns
from crypto import Crypto
from server import Server
from network import NetworkFieldsSize, NetworkCodes


# key_file = open('/home/rar/Desktop/Keys/blockmesh_node_0.key','r')
# private_key = serialization.load_pem_private_key(key_file.read(),None, default_backend())


# message = '{"previousBlockHash":"0000000000000000000000000000000000000000000000000000000000000000","date":1451606400,"header":{"IDENTIFICATION":["be7336c2d3959231d4da5f2e7f7b6f109babaf923f4d695cb6b7827c02f4d6bb","f980e79f6ac6d01e34a341f74fc088aa9e72b02ebee6a9fef39039390c1057be","f1c5a4bad72e895115684773ce834ed29a8f223941ea8d0823ec1bf61c759f9a","3b820e5ba3f658b62b82c46f1e12ab4efa40f204f5f466b796c7b10bfc19ab0c","cba14314c2a92038a6463246a56d8f2e48afb8393209ade84c4e9abad5301120","3173723b8cd28d44ce9f8675ee087c7878b5b4579633b77732f241e6a18916b3","5f10c1b1572f18e9a8485e57efb9e49e381321b6bb5707883ee254eb932b0711"],"NETWORK":["c437e86ab7201b8d4e5b3bfb316e0b602a93cf581f9701721a498f2757be921c","851792560154753fde0315eeae9e6faae4e93431bf4b153dff2d064a989278fd","b5baa099cc8663c84d0dbc3e226da3d0c4389200ed659be47ea94a1439b40171","6856b78e0b68f918bff89f4987315a4d6b07838425f972ac5de72f6494f22eee","0bddbd5024f5b79383474026d9def0de1598f7c37231157821b431ed292450c1","ddf083c706780b074b62124e9f05f4c5e066e2ed7f9323130dbac174c50f383f"],"RESOURCES":["eea1933c2e36cb5d27fc033c9ced89affdf0404bbb20e0ec78112825a0e9b5d0","15d4319965f0ed04eb860bd94752104c7874ce8d78f8623c6441e76ad03164a4","ed7a0ee29f6701b22e216ddbe312d15db79e30e24a5123e0961ed3e2f0f540b2"]}}'
# print Crypto.hash(message), '\n'
# signer = private_key.signer(ec.ECDSA(hashes.SHA256()))
# signer.update(message)
# signature = signer.finalize()
# print base64.standard_b64encode(signature)
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
# print binascii.hexlify(encoded_key)
# public_numbers = public_key.public_numbers()
# public_key = ec.EllipticCurvePublicNumbers(public_numbers.x, public_numbers.y, ec.SECP521R1())
# public_key = public_key.public_key(default_backend())


#retrieve verifier and feed data
# verifier = public_key.verifier(signature, ec.ECDSA(hashes.SHA256()))
# verifier.update(message)
# print verifier.verify()

# sig = binascii.unhexlify('30818702411885e9f6dfcefcaa040793f82aa697c2611b1e38c34b6a958a96e04ae1c8d1efa5b261d3305360877b2cea2cb74e9feeb8e40388ebf3fd640adbbb030d4ef3d998024201cb0db008519b0d8f177691c56aba3a08af403d7bb98a13d1f68eeae8cfacfd59edc977e92178bb13b73b6e3a7a08a6ba24f31038ffdb9a071821181763c366b69c')
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

print NetworkCodes.IDENTIFY
msg = struct.pack('H',NetworkCodes.IDENTIFY)
print msg

print 'message type:', struct.unpack('H', msg)[0]