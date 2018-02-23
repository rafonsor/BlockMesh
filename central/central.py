from __future__ import with_statement
import xmlrpclib, SimpleXMLRPCServer, time, os, threading
from globals import Globals, Patterns
from crypto import Crypto


class RPCHandler():
	def __init__(self, DATABASE):
		self.DATABASE = DATABASE

	def new_block(self, worker, hash, signature, block):
		if not Patterns.validate(Patterns.WORKER, worker) or not Patterns.validate(Patterns.HASH, hash) or not Patterns.validate(Patterns.SIGNATURE, signature):
			return False
		with open(CONFIG['blocks_dir']+hash+'.temp', 'wb+') as temp:
			temp.write(block)
			os.fsync(temp)
			file_hash = Crypto.hash_file(temp)
			del block
		if not Crypto.verify(Globals.NETWORK_RESOURCE_CODE, NODE_ID_PREFIX+worker, file_hash, signature, 'base64'):
			os.remove(CONFIG['blocks_dir']+hash+'.temp')
			return False
		os.rename(CONFIG['blocks_dir']+hash+'.temp', CONFIG['blocks_dir']+hash+Globals.BLOCK_EXTENSION)
		self.DATABASE.new_block(hash)
		print 'New block received from worker', worker
		print 'Hash:', hash
		print 'File Signature:', signature
		return True

def RPCServer(DATABASE, host, port):
	server = SimpleXMLRPCServer.SimpleXMLRPCServer((host, port))
	print 'RPC server created'
	server.register_instance(RPCHandler(DATABASE))
	print 'Serving forever'
	return server