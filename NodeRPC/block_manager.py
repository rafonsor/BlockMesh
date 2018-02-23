from __future__ import with_statement
import threading, random, string, json, time, os, psutil
from globals import Globals, Patterns
from rpc import RPCManager
from block import Block
from server import Server


class BlockManager(threading.Thread):

	def __init__(self, CONFIG, DATABASE, CRYPTO, RPC_MANAGER, SERVER):
		threading.Thread.__init__(self)
		self.CONFIG = CONFIG
		self.DATABASE = DATABASE
		self.CRYPTO = CRYPTO
		self.RPC_MANAGER = RPC_MANAGER
		self.SERVER = SERVER
		self.LOCK = threading.Lock()
		self.blocks = []
		self.SYNC = False
		self.running = False
		self.duty_check = False
		self.next_worker = None
		self.previous_worker = None
		self.takeover_count = 0
		self.next_timestamp = 0
		print '\nBlock Manager created'

	def shutdown(self):
		self.running = False
		print 'removing unclosed blocks'
		for block in self.blocks:
			del block

	def run(self):
		#set when is the next block due
		self.next_timestamp = (int(time.time()/Globals.BLOCK_CREATION_INTERVAL)+1)*Globals.BLOCK_CREATION_INTERVAL
		while self.running:
			now = int(time.time())
			print 'now: ',now,', next block:', self.next_timestamp, 'duty:', self.next_worker
			if now >= self.next_timestamp + Globals.BLOCK_DUTY_DELAY and self.duty_check:
				self.duty_check = False
				self.next_timestamp += Globals.BLOCK_CREATION_INTERVAL
				if self.check_next_worker(self.previous_worker, self.CONFIG['id']):
					self.next_worker = self.CONFIG['id']
					self.RPC_MANAGER.broadcast_duty()

			elif now >= self.next_timestamp and not self.duty_check:
				self.duty_check = True
				self.previous_worker = self.next_worker
				if self.next_worker == self.CONFIG['id']:
					self.next_worker = None
					print 'my turn to create'
					created = False
					retries = 0
					while not created and retries < Globals.MAXIMUM_RETRIES:
						self.blocks[0].closed = True
						next_block = self.blocks[0].create_block(self.next_timestamp)
						#new block successfully created
						if next_block == None:
							#empty block, dircarded
							created = True
							break
						elif next_block:
							self.RPC_MANAGER.broadcast_block(next_block)
							self.blocks.pop(0)
							#no open blocks, create a new one
							if len(self.blocks) == 0 or sum(1 for block in self.blocks if block.connected) == 0:
								self.new_block()
							#add items to database							
							self.DATABASE.new_block(next_block)
							break
						retries += 1
					if not created:
						#failure to create block, migrate to next try
						if len(self.blocks) == 1:
							self.new_block()
						self.blocks[1].migrate(self.blocks[0])
						self.blocks.pop(0)

			else:
				#verify we're not the only node up
				if self.RPC_MANAGER.online_count():
					if self.next_worker != None and self.next_timestamp - now < Globals.BLOCK_CREATION_TAKEOVER and self.next_worker != self.CONFIG['id'] and not self.RPC_MANAGER.is_online(self.next_worker) and self.check_next_worker(self.next_worker, self.CONFIG['id']):
						#if we know who is the next worker and if he is offline, takeover his duty if we are its successor
						self.takeover_count += 1
						if self.takeover_count == Globals.BLOCK_TAKEOVER_COUNT:
							self.next_worker = self.CONFIG['id']
							self.RPC_MANAGER.broadcast_duty()
							self.takeover_count = 0
				#we take over the responsability since we're the only node online
				elif self.next_worker == None:
					self.next_worker = self.CONFIG['id']
					self.RPC_MANAGER.broadcast_duty()					
			time.sleep(0.5)

	def new_block(self):
		print 'creating new block'
		folder = ''.join(random.sample(string.lowercase, 10))+'/'
		print 'chose folder'
		print 'appending new block'
		self.blocks.append(Block(self.CONFIG, self.CRYPTO, folder))
		print 'block appended'
		self.blocks[len(self.blocks)-1].latest_block(self.DATABASE.current_block())
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

	def register_header(self, hash):
		#fetch file
		try:
			size = os.path.getsize(self.CONFIG['blocks_dir']+hash+Globals.BLOCK_EXTENSION)
			block = open(self.CONFIG['blocks_dir']+hash+Globals.BLOCK_EXTENSION, 'rb')
			if size < psutil.virtual_memory().available / Globals.JSON_MEMORY_MULTIPLIER:
				#enough memory to load header
				block_json = json.loads(block.read())
				block.close()
				#verify data fields
				previous_hash = block_json['previousBlockHash']
				signature =  block_json['signature']
				if not Patterns.validate(Patterns.HASH, previous_hash) or not Patterns.validate(Patterns.TIMESTAMP, block_json['date']) or block_json['workerNode'] not in Globals.NODES or not Patterns.validate(Patterns.SIGNATURE, signature) or type(block_json['header']) is not dict:
					raise ValueError()
				header = block_json['header']
				del block_json
			else:
				#read this block's hash
				block.seek(14,0)
				current_hash = block.read(64)
				#read previous block's hash
				block.seek(23,1)
				previous_hash = block.read(64)
				#read block's date
				block.seek(9,1)
				timestamp = block.read(10)
				#read block's creator
				block.seek(14,1)
				node = block.read(1)
				#read block's signature
				block.seek(14,1)
				signature = ''
				c = ''
				while 1:
					c = block.read(1)
					if c == '"' or c == '':
						#reached end of file
						break
					signature += c
				#read header
				block.seek(11,1)
				header_json = ''
				while 1:
					c = block.read(1)
					if c == '}' or c == '':
						#reached end of file
						break
					header_json += c
				block.close()

				#verify data fields
				if hash != current_hash or not Patterns.validate(Patterns.HASH, previous_hash) or not Patterns.validate(Patterns.TIMESTAMP, timestamp) or node not in Globals.NODES	or not Patterns.validate(Patterns.SIGNATURE, signature) or len(header_json) < 2 or (header_json[:1] != '{' and header_json[-1:] != '}'):
					raise ValueError()
				header = json.load(header_json)

			#verify block's signature
			message = '{"previousBlockHash":"'+previous_hash+'","date":'+str(timestamp)+',"header":'+json.dumps(header, sort_keys=True)+'}'
			if not self.CRYPTO.verify(Globals.NETWORK_RESOURCE_CODE, Globals.NODE_ID_PREFIX+node, message, signature, 'base64'):
				raise ValueError()

			#save to database
			self.DATABASE.new_block(hash)
			#remove duplicates from block
			with self.LOCK:
				for b in self.blocks:
					b.remove_duplicates(header)

		except:
			print 'Invalid block received: ', hash
			print 'Deleting and sending a new request'
			block = self.RPC_MANAGER.nodes[self.RPC_MANAGER.random_node()].get_block(hash)
			if block:
				with open(self.CONFIG['blocks_dir']+hash+'.temp', 'wb') as temp:
					temp.write(block.data)
					os.fsync(temp)
					del block
					#register header synchronously
				os.rename(self.CONFIG['blocks_dir']+hash+'.temp', self.CONFIG['blocks_dir']+hash+Globals.BLOCK_EXTENSION)
				self.BLOCK_MANAGER.register_header(hash)


	def load_header(self, hash):
		print 'BMGR load header'
		print type(hash)
		print type(self.CONFIG['blocks_dir'])
		try:
			filename = self.CONFIG['blocks_dir']+hash+Globals.BLOCK_EXTENSION
			size = os.path.getsize(filename)
			block = open(filename, 'rb')
			if size < psutil.virtual_memory().available / Globals.JSON_MEMORY_MULTIPLIER:
				block_json = json.loads(block.read())
				return block_json['header']
			else:
				block.seek(400,0)
				c = ''
				while 1:
					c = block.read(1)
					if c == '{':
						break
				header_json = c
				while 1:
						c = block.read(1)
						header_json += c
						if c == '}':
							break
				block.close()
				return json.loads(header_json)
		except IOError:
			print '\ncould not find block', hash
			return False

	def check_next_worker(self, previous, next):
		print 'checking next worker', previous, ' and', next
		if previous == next:
			return False
		active_nodes = self.RPC_MANAGER.online_nodes()
		active_nodes.append(self.CONFIG['id'])
		active_nodes.sort()
		print 'online', active_nodes
		index = active_nodes.index(next)
		print 'index', index
		if previous < next:
			if index == 0:
				return True
			if active_nodes[index-1] <= previous:
				return True
			return False
		if index == 0 and active_nodes[len(active_nodes)-1] <= previous:
			return True
		return False

	def update_worker(self, node, timestamp): 
		print 'updating worker'
		now = int(time.time())
		if now - timestamp > Globals.BLOCK_CREATION_INTERVAL or now - timestamp < 0:
			print 'time expired'
			return
		with self.LOCK:
			if self.check_next_worker(self.previous_worker, node):
				print "yup, he's next in line"
				self.next_worker = node
			else:
				print 'nope not that guy'

	def synchronized(self, hash):
		print 'we are synchronized'
		with self.LOCK:
			if not self.SYNC:
				print 'initializing first block'
				self.SYNC = True
				self.running = True
				self.new_block()
				self.blocks[0].latest_block(hash)
				#node synchronized, can start working
				print 'starting rest server'
				self.SERVER.set_blocks_manager(self)
				self.SERVER.start()
				self.start()


