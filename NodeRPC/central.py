from __future__ import with_statement
import xmlrpclib, SimpleXMLRPCServer, time, os, threading, random
from globals import Globals, Patterns


class RPCHandler():
	def new_block(self, worker, hash, signature, block):
		if not Patterns.validate(Patterns.WORKER, worker) or not Patterns.validate(Patterns.HASH, hash) or not Patterns.validate(Patterns.SIGNATURE, signature):
			return False
		with open('central/'+hash+'.blk', 'wb+') as temp:
			temp.write(block)
			os.fsync(temp)
			del block
		print 'New block received from worker', worker
		print 'Hash:', hash
		print 'File Signature:', signature
		return True

server = SimpleXMLRPCServer.SimpleXMLRPCServer(("localhost", 25000))
print 'RPC server created'
server.register_instance(RPCHandler())
print 'Serving forever'
server.serve_forever()