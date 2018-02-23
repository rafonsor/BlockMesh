import json, os, sys, getopt, hashlib, binascii, base64, time, struct, keyword, random, string, re, shutil, network, block_manager, ssl, server, cryptography, OpenSSL, psutil, sys, json, threading, signal, time, os
from database import Database
from block_manager import BlockManager
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.backends import default_backend
from globals import Globals, Patterns
from crypto import Crypto
from server import Server
from network import NetworkFieldsSize, NetworkCodes


configuration_file = open('config.json','r')
CONFIG = json.loads(configuration_file.read())
CONFIG['id'] = str(CONFIG['id'])
configuration_file.close()

#Load database
print '\nLoading Database'
DATABASE = Database(CONFIG)

#Load encryption key
print '\nLoading encryption key'
CRYPTO = Crypto(CONFIG, DATABASE)

def new_block(self):
	print 'creating new block'
	folder = ''.join(random.sample(string.lowercase, 10))+'/'
	print 'chose folder'
	print 'appending new block'
	blocks.append(Block(CONFIG, CRYPTO, folder))
	print 'block appended'
	blocks[len(blocks)-1].latest_block(DATABASE.current_block())
	print 'new block created at', folder

def new_item(self, resource, hash, item):
	with self.LOCK:
		for block in self.blocks:
			if not block.closed:
				if block.new_item(resource, hash, item):
					return True
		#all blocks are closed, create a new one
		self.new_block()
		if self.blocks[len(block)-1].new_item(resource, hash, item):
			return True
		return False

hash = 'aa1287ce600851c5f9c3cd55363af7919230f66abbf3c112b0c14b8af50652a8'
blocks = []
new_block()
blocks[0].latest_block(hash)
