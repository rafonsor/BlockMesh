from __future__ import with_statement
import xmlrpclib, SimpleXMLRPCServer, time, os, threading, random
from globals import Globals, Patterns


class RequestHandler(SimpleXMLRPCServer.SimpleXMLRPCRequestHandler):
	rpc_paths = (Globals.RPC_PATH)

class RPCHandler():
	def __init__(self, CONFIG, DATABASE, CRYPTO, RPC_MANAGER, BLOCK_MANAGER):
		self.CONFIG = CONFIG
		self.DATABASE = DATABASE
		self.CRYPTO = CRYPTO
		self.RPC_MANAGER = RPC_MANAGER
		self.BLOCK_MANAGER = BLOCK_MANAGER

	def identify(self, worker, timestamp, signature):
		if not Patterns.validate(Patterns.WORKER, worker) or not Patterns.validate(Patterns.TIMESTAMP, timestamp) or not Patterns.validate(Patterns.SIGNATURE, signature):
			return {'status': 'refused', 'error': 'bad request'}
		now = time.time()
		if timestamp > now or timestamp < now - Globals.MAXIMUM_IDENTIFICATION_DELAY:
			return {'status': 'refused', 'error': 'invalid timestamp'}
		if not self.CRYPTO.verify(Globals.NETWORK_RESOURCE_CODE, Globals.NODE_ID_PREFIX+worker, self.CONFIG['id']+str(timestamp), signature, 'base64'):
			return {'status': 'refused', 'error': 'invalid signature'}
		(sid, validity) = self.DATABASE.new_session(worker, signature)
		return {'status': 'accepted', 'sid': sid, 'validity': validity}

	def get_index(self):
		if os.path.isfile(self.CONFIG['blocks_index_file']):
			with open(self.CONFIG['blocks_index_file'], 'rb') as index:
				return xmlrpclib.Binary(index.read())
		return False

	def latest_block(self):
		return self.DATABASE.current_block()

	def next_block(self, hash):		
		if not Patterns.validate(Patterns.HASH, hash):
			return False
		(next_block, response) = self.DATABASE.next_block(hash)
		if response:
			if not self.CONFIG['synchronized']:
				#this other node doesn't have this block, therefore we have a more recent block, meaning we're synchronized
				with self.LOCK:
					self.CONFIG['synchronized'] = True
				self.BLOCK_MANAGER.synchronized(hash)
			return next_block
		return False

	def get_block(self, hash):
		if not Patterns.validate(Patterns.HASH, hash) or not os.path.isfile(self.CONFIG['blocks_dir']+hash+Globals.BLOCK_EXTENSION):
			return False			
		with open(self.CONFIG['blocks_dir']+hash+Globals.BLOCK_EXTENSION, 'rb') as block:
			return xmlrpclib.Binary(block.read())
		return False

	def new_block(self, worker, hash, signature, block):
		print 'receiving new block'
		print worker
		print hash
		print signature
		print len(block)
		if not Patterns.validate(Patterns.WORKER, worker) or not Patterns.validate(Patterns.HASH, hash) or not Patterns.validate(Patterns.SIGNATURE, signature):
			print 'stuff didn"t validate'
			return False
		print 'opening temp file'
		with open(self.CONFIG['blocks_dir']+hash+'.temp', 'wb+') as temp:
			print 'got temp'
			temp.write(block)
			print 'wrote into temp'
			os.fsync(temp)
			print 'synched'
			del block
			print 'deleted'
			file_hash = self.CRYPTO.hash_file(temp)
			print 'hashed'
		if not self.CRYPTO.verify(Globals.NETWORK_RESOURCE_CODE, Globals.NODE_ID_PREFIX+worker, file_hash, signature, 'base64'):
			print 'invalid signature'
			os.remove(self.CONFIG['blocks_dir']+hash+'.temp')
			return False
		print 'renaming'
		os.rename(self.CONFIG['blocks_dir']+hash+'.temp', self.CONFIG['blocks_dir']+hash+Globals.BLOCK_EXTENSION)
		print 'renamed'
		side_thread = threading.Thread(self.BLOCK_MANAGER.register_header, hash)
		side_thread.start()
		print 'started side thread'
		return True

	def set_worker(self, worker, timestamp, signature):
		print 'received broadcasting duty from worker', worker
		if not Patterns.validate(Patterns.WORKER, worker) or not Patterns.validate(Patterns.TIMESTAMP, str(timestamp)) or not Patterns.validate(Patterns.SIGNATURE, signature):
			print 'invalidated request'
			return False
		if self.CRYPTO.verify(Globals.NETWORK_RESOURCE_CODE, Globals.NODE_ID_PREFIX+worker, str(timestamp), signature, 'base64'):
			print 'signature validated'
			self.BLOCK_MANAGER.update_worker(worker, timestamp)
			return True
		print 'invalid signature'
		return False

	def get_worker(self):
		return self.BLOCK_MANAGER.next_worker

	def online(self):
		if not self.CONFIG['synchronized']:
			#they have one block we don't, then we need to synchronize with them
			side_thread = threading.Thread(target=self.RPC_MANAGER.synchronize)
			side_thread.start()
		return True


class RPCManager():

	def __init__(self, CONFIG, DATABASE, CRYPTO):
		self.CONFIG = CONFIG
		self.DATABASE = DATABASE
		self.CRYPTO = CRYPTO
		self.LOCK = threading.Lock()

	def shutdown(self):
		print 'shutting down RPC server'
		self.server.shutdown()
		for node in self.nodes:
			del node

	def connect(self, BLOCK_MANAGER):
		self.BLOCK_MANAGER = BLOCK_MANAGER
		self.nodes = {}
		for node in self.CONFIG['nodes']:
			self.nodes[node['node']] = xmlrpclib.Server('http://'+node['host']+':'+str(node['port'])+Globals.RPC_PATH)
		
		self.CONFIG['synchronized'] = False
		if self.online_count():
			self.synchronize()
		else:
			self.BLOCK_MANAGER.next_worker = self.CONFIG['id']
			self.BLOCK_MANAGER.previous_worker = self.CONFIG['id']
			
		#RPC Server
		self.server = SimpleXMLRPCServer.SimpleXMLRPCServer(("localhost", self.CONFIG['network_port']), requestHandler=RequestHandler)
		self.server.register_instance(RPCHandler(self.CONFIG, self.DATABASE, self.CRYPTO, self, self.BLOCK_MANAGER))
		self.server_thread = threading.Thread(target=self.server.serve_forever)
		self.server_thread.start()
		print 'serving RPC server'

	def online_count(self):
		count = 0
		with self.LOCK:
			for node in self.nodes:
				if self.is_online(node):
					count += 1
		return count

	def online_nodes(self):
		nodes = []
		for node in self.nodes:
			if self.is_online(node):
				print node, 'is online'
				nodes.append(node)
			else:
				print node, 'is not online'
		print 'returning online nodes'
		return nodes

	def is_online(self, node):
		for it in range(3):
			try:
				if self.nodes[node].online():
					print 'node', node, 'is online'
					return True
			except:		
				for worker in self.CONFIG['nodes']:
					if node == worker:
						self.nodes[node] = xmlrpclib.Server('http://'+worker['host']+':'+str(worker['port'])+Globals.RPC_PATH)
						try:
							if self.nodes[node].online():
								return True
						except:
							continue
		return False

	def random_node(self):
		print 'fetching a node'
		online = []
		with self.LOCK:
			for node in self.nodes:
				if self.is_online(node):
					online.append(node)
			if len(online) == 0:
				return False
		return random.choice(online)

	def synchronize(self):
		print 'synchronizing with RPC'
		current_block = self.DATABASE.current_block()
		while not self.CONFIG['synchronized']:
			try:
				worker = self.random_node()
				if not worker:
					break
				if current_block == self.nodes[worker].latest_block():
					print 'current is latest'
					if self.BLOCK_MANAGER.next_worker == None:
						self.BLOCK_MANAGER.next_worker = self.nodes[worker].get_worker()
						self.BLOCK_MANAGER.previous_worker = self.BLOCK_MANAGER.next_worker
					self.CONFIG['synchronized'] = True
					self.BLOCK_MANAGER.synchronized(current_block)
					break
				next_block = self.nodes[worker].next_block(current_block)
				print 'next_block', next_block
				if not next_block:
					print 'no next block'
					#current block is invalid, therefore our index file is corrupt
					#we need to get a new index file, reconstruct our database and synchronize
					#or we have a newer block...
					break

				block = self.nodes[worker].get_block(next_block)
				print 'got that block', block
				if block:
					print 'exists'
					with open(self.CONFIG['blocks_dir']+next_block+'.temp', 'wb') as temp:
						print 'saving'
						temp.write(block.data)
						os.fsync(temp)
						del block
						#register header synchronously
					os.rename(self.CONFIG['blocks_dir']+next_block+'.temp', self.CONFIG['blocks_dir']+next_block+Globals.BLOCK_EXTENSION)
					self.BLOCK_MANAGER.register_header(next_block)
				#repeat until latest
				current_block = next_block
				print 'replaced and restarting'
			except Exception as e:
				print 'some exception'
				#RPC call error, repeat with another random node
				continue

	def broadcast_duty(self):
		print 'broadcasting duty'
		timestamp = int(time.time())
		signature = self.CRYPTO.sign(str(timestamp), 'base64')
		with self.LOCK:
			for node in self.nodes:
				if self.is_online(node):
					try:
						self.nodes[node].set_worker(self.CONFIG['id'], timestamp, signature)
					except:
						continue

	def broadcast_block(self, hash):
		with open(self.CONFIG['blocks_dir']+hash+Globals.BLOCK_EXTENSION, 'rb') as block:
			file_hash = self.CRYPTO.hash_file(block)
			print 'file hash:', file_hash
			signature = self.CRYPTO.sign(file_hash, 'base64')
			print 'file sig:', signature
			print 'verifying my own signature:', self.CRYPTO.verify(Globals.NETWORK_RESOURCE_CODE, Globals.NODE_ID_PREFIX+str(	self.CONFIG['id']), file_hash, signature, 'base64')
			with self.LOCK:
				print 'have lock'
				for node in self.nodes:
					if self.is_online(node):
						try:
							print 'putting to 0,0'
							block.seek(0,0)
							print 'sending block'
							self.nodes[node].new_block(self.CONFIG['id'], hash, signature, block.read())
							print 'block sent'
						except Exception as e:
							print 'Exception at broadcast_block', e
							continue

			#publish to subscribers
			try:
				print 'connecting to central'
				central = xmlrpclib.Server('http://127.0.0.1:25000/')
				print 'putting to 0,0'
				block.seek(0,0)
				print 'sending block to central'
				central.new_block(self.CONFIG['id'], hash, signature, block.read())
			except Exception as e:
				print 'could not send to central'
				print e
